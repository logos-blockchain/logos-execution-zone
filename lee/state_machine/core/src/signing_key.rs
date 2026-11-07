use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum KeyType {
    Schnorr = 1,
}

/// 32-byte commitment to a signing key; its encoding/decoding depends on the `KeyType`.
pub type KeyCommitment = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SigningKeyState {
    pub key_type: KeyType,
    pub key_commitment: KeyCommitment,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_type_encodes_to_its_discriminant_byte() {
        let bytes = borsh::to_vec(&KeyType::Schnorr).unwrap();
        assert_eq!(bytes, [1]);
        assert_eq!(
            borsh::from_slice::<KeyType>(&bytes).unwrap(),
            KeyType::Schnorr
        );
    }

    #[test]
    fn signing_key_state_encodes_to_33_bytes() {
        let state = SigningKeyState {
            key_type: KeyType::Schnorr,
            key_commitment: [0; 32],
        };
        let bytes = borsh::to_vec(&state).unwrap();
        assert_eq!(bytes, [&[1][..], &[0; 32][..]].concat());
        assert_eq!(borsh::from_slice::<SigningKeyState>(&bytes).unwrap(), state);
    }

    #[test]
    fn decoding_rejects_unknown_key_type() {
        assert_eq!(
            borsh::from_slice::<KeyType>(&[0]).unwrap_err().to_string(),
            "Unexpected variant tag: 0"
        );
        assert_eq!(
            borsh::from_slice::<SigningKeyState>(&[&[2][..], &[0; 32][..]].concat())
                .unwrap_err()
                .to_string(),
            "Unexpected variant tag: 2"
        );
    }

    #[test]
    fn decoding_rejects_wrong_length() {
        assert_eq!(
            borsh::from_slice::<SigningKeyState>(&[1; 32])
                .unwrap_err()
                .to_string(),
            "Unexpected length of input"
        );
        assert_eq!(
            borsh::from_slice::<SigningKeyState>(&[1; 34])
                .unwrap_err()
                .to_string(),
            "Not all bytes read"
        );
    }
}
