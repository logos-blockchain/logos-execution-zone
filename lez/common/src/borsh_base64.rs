//! This module provides utilities for serializing and deserializing data by combining Borsh and
//! Base64 encodings.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub fn serialize<T: BorshSerialize, S: serde::Serializer>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let borsh_encoded = borsh::to_vec(value).map_err(serde::ser::Error::custom)?;
    let base64_encoded = STANDARD.encode(&borsh_encoded);
    Serialize::serialize(&base64_encoded, serializer)
}

pub fn deserialize<'de, T: BorshDeserialize, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<T, D::Error> {
    let base64_encoded = <String as Deserialize>::deserialize(deserializer)?;
    let borsh_encoded = STANDARD
        .decode(base64_encoded.as_bytes())
        .map_err(serde::de::Error::custom)?;
    borsh::from_slice(&borsh_encoded).map_err(serde::de::Error::custom)
}
