use std::{fmt, str::FromStr};

use borsh::{BorshDeserialize, BorshSerialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::{
    account::{AccountId, ActorState},
    program::SystemProgramName,
};

pub const SIGNATURE_PROGRAM_NAME: SystemProgramName = SystemProgramName::new(b"signature");

/// Messages to an account's signature actor. Append only.
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
    Schnorr = 0,
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

impl SigningKeyState {
    /// This key as the signature program's actor state.
    #[must_use]
    pub fn encode(self) -> ActorState {
        ActorState::from(borsh::to_vec(&self).expect("a signing key state encodes to 33 bytes"))
    }

    /// The key a signature program's actor state holds.
    pub fn decode(state: &ActorState) -> Result<Self, borsh::io::Error> {
        borsh::from_slice(state)
    }
}

/// The address of `signature_program`, the `system_upgrader` PDA for its name. Its actor state
/// holds each account's signing key.
#[must_use]
pub fn signature_program_id() -> AccountId {
    AccountId::from_system_program_name(&SIGNATURE_PROGRAM_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_type_encodes_to_its_discriminant_byte() {
        let bytes = borsh::to_vec(&KeyType::Schnorr).unwrap();
        assert_eq!(bytes, [0]);
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
        assert_eq!(bytes, [&[0][..], &[0; 32][..]].concat());
        assert_eq!(borsh::from_slice::<SigningKeyState>(&bytes).unwrap(), state);
    }

    #[test]
    fn decoding_rejects_unknown_key_type() {
        assert_eq!(
            borsh::from_slice::<KeyType>(&[1]).unwrap_err().to_string(),
            "Unexpected variant tag: 1"
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
            borsh::from_slice::<SigningKeyState>(&[0; 32])
                .unwrap_err()
                .to_string(),
            "Unexpected length of input"
        );
        assert_eq!(
            borsh::from_slice::<SigningKeyState>(&[0; 34])
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
        assert_eq!(bytes, [&[0, 0][..], &[7; 32][..]].concat());
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
        let actor_state = state.encode();
        assert_eq!(actor_state.as_ref(), [&[0][..], &[7; 32][..]].concat());
        assert_eq!(SigningKeyState::decode(&actor_state).unwrap(), state);
    }

    #[test]
    fn an_actor_state_of_another_shape_is_not_a_signing_key_state() {
        for (bytes, error) in [
            (Vec::new(), "Unexpected length of input"),
            (vec![0; 32], "Unexpected length of input"),
            (vec![0; 34], "Not all bytes read"),
            (
                [&[1][..], &[7; 32][..]].concat(),
                "Unexpected variant tag: 1",
            ),
        ] {
            assert_eq!(
                SigningKeyState::decode(&ActorState::from(bytes))
                    .unwrap_err()
                    .to_string(),
                error
            );
        }
    }
}
