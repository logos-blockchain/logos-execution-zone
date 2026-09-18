//! Length-prefixed byte framing for the zkVM I/O format.
//!
//! A frame is a 4-byte little-endian length prefix followed by the payload bytes. The same
//! [`to_frame`] layout is used by the guest journal commit, the circuit's `env::verify`
//! reconstruction, and the host input write.

/// Frames `payload`'s borsh serialization as [`to_frame`] would, but serializes directly into
/// one exact-sized buffer instead of copying an intermediate payload vector.
#[must_use]
pub fn to_borsh_frame<T: borsh::BorshSerialize>(payload: &T) -> Vec<u8> {
    let len = borsh::object_length(payload).expect("borsh serialization is infallible");
    let mut framed = Vec::with_capacity(len.checked_add(4).expect("length overflow"));
    framed.extend_from_slice(
        &u32::try_from(len)
            .expect("frame payload length must fit in u32")
            .to_le_bytes(),
    );
    borsh::to_writer(&mut framed, payload).expect("borsh serialization is infallible");
    framed
}

/// Frames `payload` as a 4-byte little-endian length prefix followed by the payload bytes.
#[must_use]
pub fn to_frame(payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame payload length must fit in u32");
    let mut framed = len.to_le_bytes().to_vec();
    framed.extend_from_slice(payload);
    framed
}

/// Returns the payload slice of a frame produced by [`to_frame`] or [`to_borsh_frame`].
///
/// Returns `None` if `bytes` is shorter than the 4-byte length prefix or the prefixed
/// length exceeds the available payload.
#[must_use]
pub fn from_frame(bytes: &[u8]) -> Option<&[u8]> {
    let (len_bytes, payload) = bytes.split_at_checked(4)?;
    let len = usize::try_from(u32::from_le_bytes(len_bytes.try_into().ok()?)).ok()?;
    payload.get(..len)
}

#[cfg(test)]
mod tests {
    use super::{from_frame, to_borsh_frame, to_frame};

    #[test]
    fn to_borsh_frame_matches_framed_to_vec() {
        let payload: (u32, Vec<u8>, Option<[u8; 32]>) = (7, vec![1, 2, 3], Some([42; 32]));
        assert_eq!(
            to_borsh_frame(&payload),
            to_frame(&borsh::to_vec(&payload).unwrap())
        );
    }

    #[test]
    fn frame_round_trip() {
        let payload: &[u8] = b"hello borsh boundary";
        let framed = to_frame(payload);
        assert_eq!(from_frame(&framed).unwrap(), payload);
    }

    #[test]
    fn from_frame_ignores_bytes_after_the_payload() {
        let payload: &[u8] = &[1, 2, 3, 4, 5, 6, 7];
        let mut framed = to_frame(payload);
        // The prefix delimits the payload; whatever follows belongs to another frame.
        framed.extend_from_slice(&[0, 0, 0]);
        assert_eq!(from_frame(&framed).unwrap(), payload);
    }

    #[test]
    fn empty_payload_round_trips() {
        let framed = to_frame(&[]);
        assert_eq!(framed, vec![0, 0, 0, 0]);
        assert!(from_frame(&framed).unwrap().is_empty());
    }

    #[test]
    fn from_frame_rejects_malformed() {
        assert!(from_frame(&[]).is_none()); // shorter than the 4-byte prefix
        assert!(from_frame(&[1, 2, 3]).is_none());
        // length prefix claims more bytes than the payload holds
        assert!(from_frame(&[0xFF, 0xFF, 0xFF, 0x7F, 0x00]).is_none());
    }
}
