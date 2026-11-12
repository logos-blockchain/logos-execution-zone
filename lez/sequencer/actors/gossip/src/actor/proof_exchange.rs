use std::io;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use lee::privacy_preserving_transaction::circuit::{Proof, ProofDigest};
use libp2p::request_response;
use sequencer_core::config::MAX_PUBLISHABLE_BLOCK_SIZE;

const REQUEST_SIZE: usize = 32;
// A proof a block can carry, behind borsh's `Some` tag and `u32` length.
const MAX_RESPONSE_SIZE: u64 = MAX_PUBLISHABLE_BLOCK_SIZE.saturating_add(5);

#[derive(Clone)]
pub struct ProofCodec;

#[async_trait]
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
