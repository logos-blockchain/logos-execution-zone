use std::{fmt::Display, str::FromStr};

use borsh::{BorshDeserialize, BorshSerialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

pub mod block;
mod borsh_base64;
pub mod bounded_vec_deque;
pub mod config;
pub mod transaction;

// Module for tests utility functions
//
// TODO: Compile only for tests
pub mod test_utils;

#[derive(
    Default,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    SerializeDisplay,
    DeserializeFromStr,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct HashType(pub [u8; 32]);

impl Display for HashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for HashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for HashType {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl AsRef<[u8]> for HashType {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<HashType> for [u8; 32] {
    fn from(hash: HashType) -> Self {
        hash.0
    }
}

impl From<[u8; 32]> for HashType {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<Vec<u8>> for HashType {
    type Error = <[u8; 32] as TryFrom<Vec<u8>>>::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl From<HashType> for Vec<u8> {
    fn from(hash: HashType) -> Self {
        hash.0.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization_roundtrip() {
        let original = HashType([1_u8; 32]);
        let serialized = original.to_string();
        let deserialized = HashType::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn as_ref_returns_exact_inner_bytes() {
        // `HashType::as_ref` must return exactly the inner `[u8; 32]` — not an
        // empty slice or a placeholder. Catches mutations of `as_ref` that return
        // `Vec::leak(Vec::new())`, `vec![0]`, or `vec![1]`.
        let known = [0x42_u8; 32];
        let hash = HashType(known);
        assert_eq!(hash.as_ref(), &known);
        assert_eq!(hash.as_ref().len(), 32);
        assert_eq!(HashType([0_u8; 32]).as_ref().len(), 32);
    }
}
