//! Reexports of types used by sequencer rpc specification.

use std::{fmt::Display, str::FromStr};

pub use common::{
    HashType, PageLimit,
    block::{Block, TransactionReceipt},
    transaction::LeeTransaction,
};
pub use lee::{Account, AccountData, AccountId, Actor, EncryptedNote, ProgramId, Publication};
pub use lee_core::{
    BlockId, Commitment, CommitmentPosition, CommitmentSetDigest, MembershipProof, Nullifier,
    account::Nonce,
};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay, hex::Hex, serde_as};

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChannelId(#[serde_as(as = "Hex")] pub [u8; 32]);

/// The fee market priced off the head state: what a public transaction sizes
/// its `max_fee` against, and what a private transaction prices its in-proof
/// fee at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeStateQuote {
    /// The height of the quoted fee state, for staleness checks.
    pub height: u64,
    /// Execution base fee at `height`, per cycle.
    pub base_fee_exec: u64,
    /// Storage base fee at `height`, per byte.
    pub base_fee_stor: u64,
    /// Lowest possible execution base fee of the next block: the market stepped
    /// once at an empty block. The block being filled is not observable at
    /// query time, so the next-block figures are a band, not an estimate.
    pub next_base_fee_exec_floor: u64,
    /// Highest possible execution base fee of the next block: the market
    /// stepped once at a block filled to its caps.
    pub next_base_fee_exec_ceiling: u64,
    /// Lowest possible storage base fee of the next block.
    pub next_base_fee_stor_floor: u64,
    /// Highest possible storage base fee of the next block.
    pub next_base_fee_stor_ceiling: u64,
    /// Per-block execution gas cap; no transaction may declare more.
    pub max_gas_exec: u64,
    /// Per-block storage gas cap; no transaction may carry more bytes.
    pub max_gas_stor: u64,
}

/// A cross-zone delivery a sequencer gave up on after repeated failures.
///
/// Identifies the message rather than carrying it: zone, block id and tx index
/// locate it on the peer's channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossZoneDeadLetter {
    pub message_key: HashType,
    pub src_zone: ChannelId,
    pub src_block_id: u64,
    pub src_tx_index: u32,
    pub failed_attempts: u32,
    pub transaction_bytes: u32,
}

/// What a sequencer has given up delivering.
///
/// `total_retired` counts every give-up, `retained` only the ones still kept;
/// they diverge on eviction and on reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossZoneDeadLetterReport {
    pub total_retired: u64,
    pub retained: Vec<CrossZoneDeadLetter>,
}

/// What requeueing a dead-lettered delivery did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossZoneDeadLetterRequeue {
    /// Restored to the pending list with a clean attempt count; the next
    /// production turn attempts it again.
    Requeued,
    /// The delivery was already pending again, so only the dead letter was
    /// dropped.
    AlreadyPending,
    /// No retained dead letter under that key.
    NotFound,
    /// Listed, but its transaction exceeded the retention bound and was not
    /// kept; read the message back off the peer channel instead.
    NotRetained,
}

/// What the sequencer is doing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum SequencerStatus {
    /// Replaying the channel's finalized history up to the last slot the Bedrock node has
    /// finalized.
    #[serde(rename_all = "camelCase")]
    Bootstrapping {
        /// The Bedrock slot bootstrapping completes at: the last one the node had finalized, as
        /// of the latest batch. [`None`] before the first batch.
        target_slot: Option<u64>,
        /// The Bedrock slot the finalized history is replayed up to, [`None`] before the first
        /// batch.
        replayed_up_to_slot: Option<u64>,
        /// Height of the chain replayed so far, [`None`] while it is empty.
        height: Option<BlockId>,
    },
    /// Following the channel and producing blocks on its turns.
    #[serde(rename_all = "camelCase")]
    Online { height: BlockId, is_our_turn: bool },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_serialize_as_lowercase_hex() {
        let channel_id = ChannelId([0xab; 32]);
        let json = serde_json::to_string(&channel_id).unwrap();

        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        assert_eq!(
            serde_json::from_str::<ChannelId>(&json).unwrap(),
            channel_id
        );
    }

    #[test]
    fn status_is_tagged_by_state() {
        let status = SequencerStatus::Bootstrapping {
            target_slot: Some(7),
            replayed_up_to_slot: None,
            height: Some(3),
        };

        assert_eq!(
            serde_json::to_value(&status).unwrap(),
            serde_json::json!({
                "state": "bootstrapping",
                "targetSlot": 7,
                "replayedUpToSlot": null,
                "height": 3,
            })
        );
    }
}

/// A sequencer's Ed25519 public key, hex on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, SerializeDisplay, DeserializeFromStr)]
pub struct SequencerPublicKey(pub [u8; 32]);

impl Display for SequencerPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for SequencerPublicKey {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}

/// Bytes, hex on the wire.
#[derive(Debug, Clone, PartialEq, Eq, SerializeDisplay, DeserializeFromStr)]
pub struct HexBytes(pub Vec<u8>);

impl Display for HexBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl FromStr for HexBytes {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(s.trim()).map(Self)
    }
}

/// The `system_upgrader` changes a sequencer holds committee approvals of.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemProposalReport {
    /// Approvals the committee must reach for a change.
    pub threshold: u32,
    pub proposals: Vec<SystemProposal>,
}

/// A proposed `system_upgrader` change and the approvals held of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemProposal {
    /// SHA-256 of the proposal's bytes, as `approve_system_change` prints it.
    pub proposal_hash: HashType,
    /// The proposal, borsh-encoded.
    pub proposal: HexBytes,
    pub approvals: Vec<SystemProposalApproval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemProposalApproval {
    pub signer: SequencerPublicKey,
    pub valid_until: u64,
}
