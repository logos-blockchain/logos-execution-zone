//! This crate defines the protocol types used by the indexer service.
//!
//! Currently it mostly mimics types from `lee_core`, but it's important to have a separate crate
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
    pub program_owner: AccountId,
    pub balance: u128,
    pub data: Data,
    pub nonce: Nonce,
}

pub type BlockId = u64;
pub type Timestamp = u64;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub bedrock_status: BedrockStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct BlockHeader {
    pub block_id: BlockId,
    pub prev_block_hash: HashType,
    pub hash: HashType,
    pub timestamp: Timestamp,
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
    pub program_account_id: AccountId,
    pub account_ids: Vec<AccountId>,
    pub nonces: Vec<Nonce>,
    pub instruction_data: InstructionData,
    /// Empty when absent — see `lee::public_transaction::Message::raw_payload`'s doc comment for
    /// what this carries.
    pub raw_payload: Vec<u8>,
}

pub type InstructionData = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PublicActionWithID {
    pub account_id: AccountId,
    pub post_state: Account,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PrivateAction {
    pub nullifier: Nullifier,
    pub root: CommitmentSetDigest,
    // IMPORTANT: The commitment in the action is not necessarily connected
    // to the nullifier in content. That is, the commitment's plaintext is
    // not necessarily the updated account state of the nullifier's plaintext.
    pub commitment: Commitment,
    pub encrypted_post_state: EncryptedAccountData,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PrivacyPreservingMessage {
    pub public_actions: Vec<PublicActionWithID>,
    pub nonces: Vec<Nonce>,
    pub private_actions: Vec<PrivateAction>,
    pub block_validity_window: ValidityWindow,
    pub timestamp_validity_window: ValidityWindow,
    pub program_image_claims: Vec<ProgramImageClaim>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ProgramImageClaim {
    pub account_id: AccountId,
    pub image_id: ProgramId,
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
pub struct ValidityWindow(pub (Option<BlockId>, Option<BlockId>));

impl Display for ValidityWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            (Some(start), Some(end)) => write!(f, "[{start}, {end})"),
            (Some(start), None) => write!(f, "[{start}, \u{221e})"),
            (None, Some(end)) => write!(f, "(-\u{221e}, {end})"),
            (None, None) => write!(f, "(-\u{221e}, \u{221e})"),
        }
    }
}

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
pub enum BedrockStatus {
    Pending,
    Safe,
    Finalized,
}

/// Coarse lifecycle state of the indexer's ingestion loop, so a client can tell
/// "still catching up" apart from "something went wrong".
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum IndexerSyncState {
    /// Booted; no ingestion cycle has run yet.
    Starting,
    /// Streaming finalized messages toward the L1 frontier.
    Syncing,
    /// Drained the stream up to the last finalized block; idle until new blocks finalize.
    CaughtUp,
    /// The last cycle failed (e.g. the L1 node is unreachable). See `last_error`.
    Error,
    /// Parked on a stall reason: the validated tip is frozen awaiting a valid
    /// continuation. See `last_error` and `stall_reason`.
    Stalled,
    /// Ingestion ended on a cross-zone verdict. See `last_error` and
    /// `cross_zone_halt`.
    Halted,
    /// A state this client build does not know: a newer server added one.
    /// Treat it as "not known healthy" rather than failing to decode the
    /// snapshot.
    #[serde(other)]
    Unknown,
}

/// Durable record of a cross-zone verification halt: the local block whose
/// dispatch failed re-derivation, the dispatch's source coordinates, and the
/// verdict.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CrossZoneHalt {
    /// The local block whose dispatch failed.
    pub block_id: BlockId,
    pub block_hash: HashType,
    /// Hex id of the dispatch's source zone.
    pub src_zone: String,
    pub src_block_id: u64,
    pub src_tx_index: u32,
    pub verdict: String,
}

/// Coarse health of one peer-zone reader.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum PeerHealth {
    /// The last pass drained with no stall and the cursor at the channel tip.
    Live,
    /// No caught-up evidence yet.
    Lagging,
    /// Stuck on a slot it cannot read.
    Holed,
    /// A verified-absence verdict was issued against this peer's chain.
    Halted,
}

/// One peer reader's snapshot: how far the peer chain is verified, where the
/// read cursor is, and a coarse health classification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PeerStatus {
    /// Hex id of the peer zone.
    pub zone: String,
    pub verified_tip_block_id: Option<u64>,
    pub cursor_slot: Option<u64>,
    pub stuck_slot_attempts: u32,
    pub health: PeerHealth,
}

/// Why the indexer could not apply an L2 block from the channel.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum BlockIngestError {
    Deserialize(String),
    UnexpectedBlockId {
        expected: u64,
        got: u64,
    },
    BrokenChainLink {
        expected_prev: HashType,
        got_prev: HashType,
    },
    HashMismatch {
        computed: HashType,
        header: HashType,
    },
    EmptyBlock,
    InvalidClockTransaction,
    NonPublicGenesisTransaction,
    StateTransition {
        /// Index of the failing transaction within the block body.
        tx_index: u64,
        reason: String,
    },
}

/// Diagnostic record of the first block that broke the L2 chain.
///
/// The block-derived fields are `None` for a deserialize break (no header was
/// ever parsed). `l1_slot` is the L1 slot the breaking inscription was read at.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct StallReason {
    pub block_id: Option<u64>,
    pub block_hash: Option<HashType>,
    pub prev_block_hash: Option<HashType>,
    pub l1_slot: u64,
    pub error: BlockIngestError,
    /// The breaking block's L2 timestamp (`None` for a deserialize break).
    pub first_seen: Option<Timestamp>,
    /// Number of later non-chaining blocks seen while the tip is frozen.
    pub orphans_since: u64,
}

/// Status snapshot returned by `getStatus`: the ingestion state plus the
/// indexed L2 tip and, when stalled or halted, the diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct IndexerStatus {
    pub state: IndexerSyncState,
    pub last_error: Option<String>,
    pub indexed_block_id: Option<BlockId>,
    pub stall_reason: Option<StallReason>,
    /// Present while ingestion is halted on a cross-zone verdict.
    #[serde(default)]
    pub cross_zone_halt: Option<CrossZoneHalt>,
    /// One snapshot per configured peer zone; empty with cross-zone disabled.
    #[serde(default)]
    pub cross_zone_peers: Vec<PeerStatus>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status() -> IndexerStatus {
        IndexerStatus {
            state: IndexerSyncState::Halted,
            last_error: Some("cross-zone verification failed".to_owned()),
            indexed_block_id: Some(8),
            stall_reason: None,
            cross_zone_halt: Some(CrossZoneHalt {
                block_id: 9,
                block_hash: HashType([0xAB; 32]),
                src_zone: hex::encode([2_u8; 32]),
                src_block_id: 5,
                src_tx_index: 1,
                verdict: "re-derivation mismatch".to_owned(),
            }),
            cross_zone_peers: vec![PeerStatus {
                zone: hex::encode([2_u8; 32]),
                verified_tip_block_id: Some(4),
                cursor_slot: Some(70),
                stuck_slot_attempts: 3,
                health: PeerHealth::Holed,
            }],
        }
    }

    #[test]
    fn indexer_status_round_trips_with_cross_zone_fields() {
        let status = status();
        let json = serde_json::to_string(&status).expect("serialize");
        let back: IndexerStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, status);
    }

    #[test]
    fn indexer_status_without_cross_zone_fields_still_deserializes() {
        // A snapshot from before these fields existed.
        let json = r#"{
            "state": "CaughtUp",
            "last_error": null,
            "indexed_block_id": 7,
            "stall_reason": null
        }"#;
        let status: IndexerStatus = serde_json::from_str(json).expect("deserialize");
        assert_eq!(status.state, IndexerSyncState::CaughtUp);
        assert_eq!(status.cross_zone_halt, None);
        assert!(status.cross_zone_peers.is_empty());
    }

    #[test]
    fn an_unknown_sync_state_deserializes_to_unknown() {
        let state: IndexerSyncState =
            serde_json::from_str(r#""SomeFutureState""#).expect("deserialize");
        assert_eq!(state, IndexerSyncState::Unknown);

        // And a whole snapshot carrying it still decodes.
        let json = r#"{
            "state": "SomeFutureState",
            "last_error": null,
            "indexed_block_id": 7,
            "stall_reason": null
        }"#;
        let status: IndexerStatus = serde_json::from_str(json).expect("deserialize");
        assert_eq!(status.state, IndexerSyncState::Unknown);
    }

    #[test]
    fn peer_health_variants_round_trip() {
        for health in [
            PeerHealth::Live,
            PeerHealth::Lagging,
            PeerHealth::Holed,
            PeerHealth::Halted,
        ] {
            let json = serde_json::to_string(&health).expect("serialize");
            let back: PeerHealth = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, health);
        }
    }
}
