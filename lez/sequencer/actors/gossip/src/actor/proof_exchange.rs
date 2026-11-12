use std::io;

use futures::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use lee::privacy_preserving_transaction::circuit::{Proof, ProofDigest};
use libp2p::request_response;
use sequencer_core::config::MAX_TRANSACTION_SIZE;

const REQUEST_SIZE: usize = 32;
// A proof a transaction can carry, behind borsh's `Some` tag and `u32` length.
const MAX_RESPONSE_SIZE: u64 = MAX_TRANSACTION_SIZE.saturating_add(5);

#[derive(Clone)]
pub struct ProofCodec;

impl request_response::Codec for ProofCodec {
    type Protocol = String;
    type Request = ProofDigest;
    type Response = Option<Proof>;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut request = [0; REQUEST_SIZE];
        io.read_exact(&mut request).await?;
        borsh::from_slice(&request)
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut response = Vec::new();
        io.take(MAX_RESPONSE_SIZE.saturating_add(1))
            .read_to_end(&mut response)
            .await?;
        if u64::try_from(response.len()).unwrap_or(u64::MAX) > MAX_RESPONSE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proof response too large",
            ));
        }
        borsh::from_slice(&response)
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&borsh::to_vec(&req)?).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&borsh::to_vec(&res)?).await
    }
}

#[must_use]
pub fn protocol_for_channel(channel_id: [u8; 32]) -> String {
    format!("/lez/{}/v1/proofs", hex::encode(channel_id))
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use libp2p::request_response::Codec as _;

    use super::*;

    fn response_with_proof_of(len: u64) -> Vec<u8> {
        let proof = Proof::from_inner(vec![0; usize::try_from(len).unwrap()]);
        borsh::to_vec(&Some(proof)).unwrap()
    }

    #[tokio::test]
    async fn a_request_is_exactly_one_digest() {
        let protocol = protocol_for_channel([0; 32]);
        let digest = Proof::from_inner(vec![0; 32]).digest();
        let mut written = Vec::new();
        ProofCodec
            .write_request(&protocol, &mut written, digest)
            .await
            .unwrap();

        let read = ProofCodec
            .read_request(&protocol, &mut Cursor::new(written.clone()))
            .await
            .unwrap();
        let short = ProofCodec
            .read_request(&protocol, &mut Cursor::new(written[1..].to_vec()))
            .await
            .unwrap_err();

        assert_eq!(written.len(), REQUEST_SIZE);
        assert_eq!(read, digest);
        assert_eq!(short.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_response_past_the_largest_proof_a_transaction_can_carry_is_refused() {
        let protocol = protocol_for_channel([0; 32]);
        let largest = response_with_proof_of(MAX_TRANSACTION_SIZE);
        let oversized = response_with_proof_of(MAX_TRANSACTION_SIZE.checked_add(1).unwrap());

        let accepted = ProofCodec
            .read_response(&protocol, &mut Cursor::new(largest.clone()))
            .await
            .unwrap();
        let refused = ProofCodec
            .read_response(&protocol, &mut Cursor::new(oversized))
            .await
            .unwrap_err();

        assert_eq!(u64::try_from(largest.len()).unwrap(), MAX_RESPONSE_SIZE);
        assert_eq!(
            accepted.map(|proof| proof.into_inner().len()),
            Some(usize::try_from(MAX_TRANSACTION_SIZE).unwrap())
        );
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
        assert_eq!(refused.to_string(), "proof response too large");
    }
}
