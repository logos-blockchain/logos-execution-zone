//! Reexports of types used by sequencer rpc specification.

pub use common::{HashType, block::Block, transaction::LeeTransaction};
pub use lee::{Account, AccountData, AccountId, ProgramId, ProgramShardSelector};
pub use lee_core::{BlockId, Commitment, CommitmentSetDigest, MembershipProof, account::Nonce};
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChannelId(#[serde_as(as = "Hex")] pub [u8; 32]);

/// Id of an entry on a Bedrock channel.
#[serde_as]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MsgId(#[serde_as(as = "Hex")] pub [u8; 32]);

/// The fee market priced off the head state, for wallets sizing `max_fee`.
///
/// TODO: Move slop struct description into by-field descriptions.
/// The next-block figures are a band rather than an estimate: the block being
/// filled is not observable at query time, so the quote steps the market once
/// at an empty block (floor) and once at a block filled to its caps (ceiling);
/// every possible next-block base fee lies between them. Fee-exempt classes
/// (private transactions, deployments) pay nothing under the interim policy
/// and are not quoted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeStateQuote {
    /// The block height the quoted state settled at, for staleness checks.
    pub height: u64,
    pub base_fee_exec: u64,
    pub base_fee_stor: u64,
    pub next_base_fee_exec_floor: u64,
    pub next_base_fee_exec_ceiling: u64,
    pub next_base_fee_stor_floor: u64,
    pub next_base_fee_stor_ceiling: u64,
    pub max_gas_exec: u64,
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
    /// Replaying the channel's finalized history up to the tip it had at startup.
    #[serde(rename_all = "camelCase")]
    Bootstrapping {
        /// The channel entry bootstrapping completes at.
        target: MsgId,
        /// The last channel entry replayed, [`None`] before the first.
        replayed_to: Option<MsgId>,
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
            target: MsgId([1; 32]),
            replayed_to: None,
            height: Some(3),
        };

        assert_eq!(
            serde_json::to_value(&status).unwrap(),
            serde_json::json!({
                "state": "bootstrapping",
                "target": "01".repeat(32),
                "replayedTo": null,
                "height": 3,
            })
        );
    }
}
