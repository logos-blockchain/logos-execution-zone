//! This crate defines the protocol types used by the indexer service.
//!
//! Currently it mostly mimics types from `nssa_core`, but it's important to have a separate crate
//! to define a stable interface for the indexer service RPCs which evolves in its own way.

use std::{fmt::Display, str::FromStr};

use anyhow::anyhow;
use base58::{FromBase58 as _, ToBase58 as _};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

#[cfg(feature = "convert")]
mod convert;

mod base64 {
    use base64::prelude::{BASE64_STANDARD, Engine as _};
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

    pub mod arr {
        use super::{Deserializer, Serializer};

        pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
            super::serialize(v, s)
        }

        pub fn deserialize<'de, const N: usize, D: Deserializer<'de>>(
            d: D,
        ) -> Result<[u8; N], D::Error> {
            let vec = super::deserialize(d)?;
            vec.try_into().map_err(|_bytes| {
                serde::de::Error::custom(format!("Invalid length, expected {N} bytes"))
            })
        }
    }

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let base64 = BASE64_STANDARD.encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        BASE64_STANDARD
            .decode(base64.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

pub type Nonce = u128;

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, SerializeDisplay, DeserializeFromStr, JsonSchema,
)]
pub struct ProgramId(pub [u32; 8]);

impl Display for ProgramId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes: Vec<u8> = self.0.iter().flat_map(|n| n.to_le_bytes()).collect();
        write!(f, "{}", bytes.to_base58())
    }
}

#[derive(Debug)]
pub enum ProgramIdParseError {
    InvalidBase58(base58::FromBase58Error),
    InvalidLength(usize),
}

impl Display for ProgramIdParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBase58(err) => write!(f, "invalid base58: {err:?}"),
            Self::InvalidLength(len) => {
                write!(f, "invalid length: expected 32 bytes, got {len}")
            }
        }
    }
}

impl FromStr for ProgramId {
    type Err = ProgramIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s
            .from_base58()
            .map_err(ProgramIdParseError::InvalidBase58)?;
        if bytes.len() != 32 {
            return Err(ProgramIdParseError::InvalidLength(bytes.len()));
        }
        let mut arr = [0_u32; 8];
        for (i, chunk) in bytes.chunks_exact(4).enumerate() {
            arr[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        Ok(Self(arr))
    }
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, SerializeDisplay, DeserializeFromStr, JsonSchema,
)]
pub struct AccountId {
    pub value: [u8; 32],
}

impl Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value.to_base58())
    }
}

impl FromStr for AccountId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s
            .from_base58()
            .map_err(|err| anyhow!("invalid base58: {err:?}"))?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "invalid length: expected 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut value = [0_u8; 32];
        value.copy_from_slice(&bytes);
        Ok(Self { value })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Account {
    pub program_owner: ProgramId,
    pub balance: u128,
    pub data: Data,
    pub nonce: Nonce,
}

pub type BlockId = u64;
pub type TimeStamp = u64;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub bedrock_status: BedrockStatus,
    pub bedrock_parent_id: MantleMsgId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct BlockHeader {
    pub block_id: BlockId,
    pub prev_block_hash: HashType,
    pub hash: HashType,
    pub timestamp: TimeStamp,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, SerializeDisplay, DeserializeFromStr, JsonSchema)]
pub struct Signature(
    #[schemars(with = "String", description = "hex-encoded signature")] pub [u8; 64],
);

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for Signature {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0_u8; 64];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct BlockBody {
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Transaction {
    Public(PublicTransaction),
    PrivacyPreserving(PrivacyPreservingTransaction),
    ProgramDeployment(ProgramDeploymentTransaction),
}

impl Transaction {
    /// Get the hash of the transaction.
    #[expect(clippy::same_name_method, reason = "This is handy")]
    #[must_use]
    pub const fn hash(&self) -> &self::HashType {
        match self {
            Self::Public(tx) => &tx.hash,
            Self::PrivacyPreserving(tx) => &tx.hash,
            Self::ProgramDeployment(tx) => &tx.hash,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PublicTransaction {
    pub hash: HashType,
    pub message: PublicMessage,
    pub witness_set: WitnessSet,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PrivacyPreservingTransaction {
    pub hash: HashType,
    pub message: PrivacyPreservingMessage,
    pub witness_set: WitnessSet,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PublicMessage {
    pub program_id: ProgramId,
    pub account_ids: Vec<AccountId>,
    pub nonces: Vec<Nonce>,
    pub instruction_data: InstructionData,
}

pub type InstructionData = Vec<u32>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PrivacyPreservingMessage {
    pub public_account_ids: Vec<AccountId>,
    pub nonces: Vec<Nonce>,
    pub public_post_states: Vec<Account>,
    pub encrypted_private_post_states: Vec<EncryptedAccountData>,
    pub new_commitments: Vec<Commitment>,
    pub new_nullifiers: Vec<(Nullifier, CommitmentSetDigest)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct WitnessSet {
    pub signatures_and_public_keys: Vec<(Signature, PublicKey)>,
    pub proof: Option<Proof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Proof(
    #[serde(with = "base64")]
    #[schemars(with = "String", description = "base64-encoded proof")]
    pub Vec<u8>,
);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct EncryptedAccountData {
    pub ciphertext: Ciphertext,
    pub epk: EphemeralPublicKey,
    pub view_tag: ViewTag,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ProgramDeploymentTransaction {
    pub hash: HashType,
    pub message: ProgramDeploymentMessage,
}

pub type ViewTag = u8;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Ciphertext(
    #[serde(with = "base64")]
    #[schemars(with = "String", description = "base64-encoded ciphertext")]
    pub Vec<u8>,
);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PublicKey(
    #[serde(with = "base64::arr")]
    #[schemars(with = "String", description = "base64-encoded public key")]
    pub [u8; 32],
);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct EphemeralPublicKey(
    #[serde(with = "base64")]
    #[schemars(with = "String", description = "base64-encoded ephemeral public key")]
    pub Vec<u8>,
);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Commitment(
    #[serde(with = "base64::arr")]
    #[schemars(with = "String", description = "base64-encoded commitment")]
    pub [u8; 32],
);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Nullifier(
    #[serde(with = "base64::arr")]
    #[schemars(with = "String", description = "base64-encoded nullifier")]
    pub [u8; 32],
);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CommitmentSetDigest(
    #[serde(with = "base64::arr")]
    #[schemars(with = "String", description = "base64-encoded commitment set digest")]
    pub [u8; 32],
);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ProgramDeploymentMessage {
    #[serde(with = "base64")]
    #[schemars(with = "String", description = "base64-encoded program bytecode")]
    pub bytecode: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Data(
    #[serde(with = "base64")]
    #[schemars(with = "String", description = "base64-encoded account data")]
    pub Vec<u8>,
);

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, SerializeDisplay, DeserializeFromStr, JsonSchema,
)]
pub struct HashType(pub [u8; 32]);

impl Display for HashType {
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct MantleMsgId(
    #[serde(with = "base64::arr")]
    #[schemars(with = "String", description = "base64-encoded Bedrock message id")]
    pub [u8; 32],
);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum BedrockStatus {
    Pending,
    Safe,
    Finalized,
}
