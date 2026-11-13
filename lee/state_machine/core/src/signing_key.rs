use std::{fmt, str::FromStr};

use borsh::{BorshDeserialize, BorshSerialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::account::{AccountId, ActorState};

/// The fixed address of `signature_program`: a native pseudo-program whose actor state holds each
/// account's signing key. Dispatched natively: only `SetKey`, from the signature program itself.
pub const SIGNATURE_PROGRAM_ID: AccountId = AccountId::new([0xFC; 32]);

/// Messages to an account's `SIGNATURE_PROGRAM_ID` actor. Append only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SignatureMessage {
    /// Replaces the account's key state with `next`, without advancing its nonce.
    SetKey { next: SigningKeyState },
}

/// Append only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum KeyType {
    Wots = 0,
    Schnorr = 1,
}

/// 32-byte commitment to a signing key; its encoding/decoding depends on the `KeyType`.
pub type KeyCommitment = [u8; 32];

/// Serialized as the hex of its 33-byte borsh encoding.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    SerializeDisplay,
    DeserializeFromStr,
)]
pub struct SigningKeyState {
    pub key_type: KeyType,
    pub key_commitment: KeyCommitment,
}

impl fmt::Display for SigningKeyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        borsh::to_vec(self)
            .expect("a signing key state encodes to 33 bytes")
            .iter()
            .try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid signing key state: expected the hex of a 33-byte encoding")]
pub struct SigningKeyStateParseError;

impl FromStr for SigningKeyState {
    type Err = SigningKeyStateParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.is_ascii() {
            return Err(SigningKeyStateParseError);
        }
        let bytes = s
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                std::str::from_utf8(pair)
                    .ok()
                    .filter(|pair| pair.len() == 2)
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                    .ok_or(SigningKeyStateParseError)
            })
            .collect::<Result<Vec<u8>, _>>()?;
        borsh::from_slice(&bytes).map_err(|_err| SigningKeyStateParseError)
    }
}

impl From<SigningKeyState> for ActorState {
    fn from(key: SigningKeyState) -> Self {
        Self::from(borsh::to_vec(&key).expect("a signing key state encodes to 33 bytes"))
    }
}

impl TryFrom<&ActorState> for SigningKeyState {
    type Error = borsh::io::Error;

    fn try_from(state: &ActorState) -> Result<Self, Self::Error> {
        borsh::from_slice(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_type_encodes_to_its_discriminant_byte() {
        for (key_type, byte) in [(KeyType::Wots, 0), (KeyType::Schnorr, 1)] {
            let bytes = borsh::to_vec(&key_type).unwrap();
            assert_eq!(bytes, [byte]);
            assert_eq!(borsh::from_slice::<KeyType>(&bytes).unwrap(), key_type);
        }
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
            borsh::from_slice::<KeyType>(&[0xFF])
                .unwrap_err()
                .to_string(),
            "Unexpected variant tag: 255"
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

    #[test]
    fn signature_message_encoding_is_pinned() {
        let message = SignatureMessage::SetKey {
            next: SigningKeyState {
                key_type: KeyType::Schnorr,
                key_commitment: [7; 32],
            },
        };
        let bytes = borsh::to_vec(&message).unwrap();
        assert_eq!(bytes, [&[0, 1][..], &[7; 32][..]].concat());
        assert_eq!(
            borsh::from_slice::<SignatureMessage>(&bytes).unwrap(),
            message
        );
    }

    #[test]
    fn a_signing_key_state_round_trips_through_an_actor_state() {
        let state = SigningKeyState {
            key_type: KeyType::Schnorr,
            key_commitment: [7; 32],
        };
        let actor_state = ActorState::from(state);
        assert_eq!(actor_state.as_ref(), [&[1][..], &[7; 32][..]].concat());
        assert_eq!(SigningKeyState::try_from(&actor_state).unwrap(), state);
    }

    #[test]
    fn an_actor_state_of_another_shape_is_not_a_signing_key_state() {
        for (bytes, error) in [
            (Vec::new(), "Unexpected length of input"),
            (vec![1; 32], "Unexpected length of input"),
            (vec![1; 34], "Not all bytes read"),
            (
                [&[2][..], &[7; 32][..]].concat(),
                "Unexpected variant tag: 2",
            ),
        ] {
            assert_eq!(
                SigningKeyState::try_from(&ActorState::from(bytes))
                    .unwrap_err()
                    .to_string(),
                error
            );
        }
    }
}
