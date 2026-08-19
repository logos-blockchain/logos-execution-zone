//! Length-prefixed byte framing for the zkVM I/O boundary.
//!
//! A frame is a 4-byte little-endian length prefix followed by the payload bytes. The same
//! [`to_frame`] layout is used by the guest journal commit, the circuit's `env::verify`
//! reconstruction, and the host input write, so all sides agree on the exact byte sequence and the
//! recursion journal digests match. [`from_frame`] recovers the payload on the host, ignoring any
//! trailing transport bytes beyond the prefixed length.

/// Frames `payload` as a 4-byte little-endian length prefix followed by the payload bytes.
#[must_use]
pub fn to_frame(payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame payload length must fit in u32");
    let mut framed = len.to_le_bytes().to_vec();
    framed.extend_from_slice(payload);
    framed
}

/// Returns the payload slice of a frame produced by [`to_frame`], ignoring any bytes past the
/// prefixed length (e.g. transport word-alignment padding).
#[must_use]
pub fn from_frame(bytes: &[u8]) -> &[u8] {
    let (len_bytes, payload) = bytes.split_at(4);
    let len = usize::try_from(u32::from_le_bytes(
        len_bytes
            .try_into()
            .expect("frame must have a 4-byte length prefix"),
    ))
    .expect("frame length must fit in usize");
    &payload[..len]
}

#[cfg(test)]
mod tests {
    use super::{from_frame, to_frame};

    #[test]
    fn frame_round_trip() {
        let payload: &[u8] = b"hello borsh boundary";
        let framed = to_frame(payload);
        assert_eq!(from_frame(&framed), payload);
    }

    #[test]
    fn frame_tolerates_trailing_padding() {
        let payload: &[u8] = &[1, 2, 3, 4, 5, 6, 7];
        let mut framed = to_frame(payload);
        // Simulate transport padding the frame up to a word boundary.
        framed.extend_from_slice(&[0, 0, 0]);
        assert_eq!(from_frame(&framed), payload);
    }

    #[test]
    fn empty_payload_round_trips() {
        let framed = to_frame(&[]);
        assert_eq!(framed, vec![0, 0, 0, 0]);
        assert!(from_frame(&framed).is_empty());
    }
}
