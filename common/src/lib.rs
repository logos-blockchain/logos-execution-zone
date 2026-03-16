use std::{fmt::Display, str::FromStr};

use borsh::{BorshDeserialize, BorshSerialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

pub mod block;
pub mod config;
pub mod error;
pub mod rpc_primitives;
pub mod sequencer_client;
pub mod transaction;

// Module for tests utility functions
// TODO: Compile only for tests
pub mod test_utils;

pub const PINATA_BASE58: &str = "EfQhKQAkX2FJiwNii2WFQsGndjvF1Mzd7RuVe7QdPLw7";

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
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(HashType(bytes))
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
        HashType(bytes)
    }
}

impl TryFrom<Vec<u8>> for HashType {
    type Error = <[u8; 32] as TryFrom<Vec<u8>>>::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(HashType(value.try_into()?))
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
        let original = HashType([1u8; 32]);
        let serialized = original.to_string();
        let deserialized = HashType::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
