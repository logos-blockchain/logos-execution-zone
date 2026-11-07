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
