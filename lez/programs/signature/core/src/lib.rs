//! Messages of the signature program's guest.

use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::signing_key::{SIGNATURE_PROGRAM_NAME, signature_program_id};
use lee_core::{account::AccountId, signing_key::SigningKeyState};

/// One account to rotate manually: the secret that owns it, and the key it gets.
#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccountRotation {
    pub secret: [u8; 32],
    pub account: AccountId,
    pub next: SigningKeyState,
}

/// Append only.
#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message {
    ManualRotation { rotations: Vec<AccountRotation> },
}

#[cfg(test)]
mod tests {
    use lee_core::signing_key::KeyType;

    use super::*;

    #[test]
    fn message_encoding_is_pinned() {
        let message = Message::ManualRotation {
            rotations: vec![AccountRotation {
                secret: [1; 32],
                account: AccountId::new([2; 32]),
                next: SigningKeyState {
                    key_type: KeyType::Schnorr,
                    key_commitment: [3; 32],
                },
            }],
        };
        let bytes = borsh::to_vec(&message).unwrap();
        assert_eq!(
            bytes,
            [
                &[0][..],      // ManualRotation
                &[1, 0, 0, 0], // one rotation
                &[1; 32],      // secret
                &[2; 32],      // account
                &[1],          // next: Schnorr
                &[3; 32],      // next: commitment
            ]
            .concat()
        );
        assert!(borsh::from_slice::<Message>(&bytes).unwrap() == message);
    }
}
