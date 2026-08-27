// TODO: Instead of `From` conversions from `protocol` types to `cell` types consider moving
// `storage` crate as sub-module in `actor` while removing `cell` types and implementing
// encoding/decoding for `protocol` structures.

use std::sync::Arc;

use common::{
    HashType,
    block::{Block, BlockMeta, PeerChainTip},
};
use lee::V03State;
use lee_core::BlockId;
use storage::sequencer::{self as db, sequencer_cells as db_cells};

use crate::Result;

/// Persists `block` with the effects it covers.
pub struct RecordNewBlock {
    pub block: Block,
    pub withdrawals: Vec<WithdrawalReconciliationKey>,
    pub state: Arc<V03State>,
    pub checkpoint_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetBlock {
    pub block_id: BlockId,
}

pub struct GetAllBlocks;

pub struct GetTransactionByHash {
    pub hash: HashType,
}

pub struct DeleteBlock {
    pub block_id: BlockId,
}

pub struct MarkBlockAsFinalized {
    pub block_id: BlockId,
}

pub struct ResetAllBlocksToPending;

pub struct GetFirstBlockId;

pub struct GetLastBlockId;

pub struct GetLatestBlockMeta;

pub struct GetLeeState;

pub struct GetZoneCheckpointBytes;

pub struct SetZoneCheckpointBytes {
    pub bytes: Vec<u8>,
}

pub struct DeleteZoneCheckpoint;

pub struct GetZoneAnchor;

pub struct SetZoneAnchor {
    pub anchor: ZoneAnchorRecord,
}

pub struct GetPublishedHighWater;

/// Raises the published high water mark to `block_id`, never lowering it.
pub struct RaisePublishedHighWater {
    pub block_id: BlockId,
}

pub struct GetPendingDepositEvents;

pub struct AddPendingDepositEvent {
    pub event: PendingDepositEventRecord,
}

pub struct GetFinalSnapshot;

/// Marks every stored pending block at or below `last_finalized` as finalized.
pub struct CleanPendingBlocksUpTo {
    pub last_finalized: BlockId,
}

pub struct ConsumeUnseenWithdrawCount {
    pub withdrawal: WithdrawalReconciliationKey,
}

pub struct GetPendingCrossZoneDispatches;

pub struct AddPendingCrossZoneDispatches {
    pub dispatches: Vec<PendingCrossZoneDispatchRecord>,
}

pub struct DropSettledCrossZoneDispatches {
    pub message_keys: Vec<[u8; 32]>,
}

pub struct RecordDispatchFailure {
    pub message_key: [u8; 32],
    pub retire_at: u32,
    pub origin: DispatchOrigin,
}

pub struct GetDeadLetterDispatches;

pub struct RequeueDeadLetterDispatch {
    pub message_key: [u8; 32],
}

pub struct GetDeadLetterDispatchCount;

pub struct GetCrossZonePeerFloorBytes {
    pub peer_zone: PeerZoneKey,
}

pub struct SetCrossZonePeerFloorBytes {
    pub peer_zone: PeerZoneKey,
    pub bytes: Vec<u8>,
}

pub struct DeleteCrossZonePeerFloor {
    pub peer_zone: PeerZoneKey,
}

pub struct GetCrossZonePeerTip {
    pub peer_zone: PeerZoneKey,
}

pub struct SetCrossZonePeerTip {
    pub peer_zone: PeerZoneKey,
    pub tip: PeerChainTip,
}

pub struct DumpDb;

/// Everything one sequencer event writes.
// TODO: Consider removing [`SetZoneCheckpointBytes`] in favor of this.
// TODO: How does this stack with [`RecordNewBlock`] ?
// TODO: Reconsider options here.
pub struct ApplyStoreUpdate {
    /// Serialized zone-sdk checkpoint for this event.
    pub checkpoint: Option<Vec<u8>>,

    /// `(block, finalized)` payloads to write.
    pub blocks: Vec<(Block, bool)>,

    /// Head tip to pin the stored chain to; `None` only for an empty chain.
    pub head_tip: Option<BlockMeta>,
    /// State after the last applied block.
    pub head_state: Arc<V03State>,

    /// `(state, meta)` of the final tier, when it advanced.
    pub final_snapshot: Option<(Arc<V03State>, BlockMeta)>,

    /// Highest block id this event made irreversible: stored blocks at or below
    /// it become finalized.
    pub finalized_up_to: Option<BlockId>,

    /// Deposit events observed on L1, recorded unless already pending.
    pub new_deposit_events: Vec<PendingDepositEventRecord>,

    /// Deposit op ids whose mint finalized: their pending records are dropped.
    pub remove_deposit_records: Vec<HashType>,
    /// Message keys whose delivery finalized: their pending records are dropped.
    pub remove_dispatch_records: Vec<[u8; 32]>,
    /// L1 withdraw events to reconcile against the local unseen counters.
    pub consumed_withdrawals: Vec<WithdrawalReconciliationKey>,
    /// L2 withdraw intents this update raises, awaiting their L1 event.
    pub new_withdraw_intents: Vec<WithdrawalReconciliationKey>,

    /// Advance the channel-read anchor.
    pub zone_anchor: Option<ZoneAnchorRecord>,
}

/// Zone id of a cross-zone peer.
pub type PeerZoneKey = [u8; 32];

/// Identity of one withdrawal: the id of the channel note it releases.
///
/// Shared by the intent recorded when the sequencer publishes a withdrawal and
/// the Bedrock event that later reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WithdrawalReconciliationKey {
    pub released_note_id: [u8; 32],
}

impl From<WithdrawalReconciliationKey> for db_cells::WithdrawalReconciliationKey {
    fn from(WithdrawalReconciliationKey { released_note_id }: WithdrawalReconciliationKey) -> Self {
        Self { released_note_id }
    }
}

impl From<db_cells::WithdrawalReconciliationKey> for WithdrawalReconciliationKey {
    fn from(
        db_cells::WithdrawalReconciliationKey { released_note_id }: db_cells::WithdrawalReconciliationKey,
    ) -> Self {
        Self { released_note_id }
    }
}

/// The last channel block read back and verified from Bedrock: the anchor for
/// the startup consistency check and the resume point for reconstruction.
///
/// `slot` is the raw L1 inscription slot; the caller converts to and from the
/// zone-sdk `Slot`, which does not derive borsh and so cannot be stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneAnchorRecord {
    pub slot: u64,
    pub block_id: u64,
    pub hash: HashType,
}

impl From<ZoneAnchorRecord> for db_cells::ZoneAnchorRecord {
    fn from(
        ZoneAnchorRecord {
            slot,
            block_id,
            hash,
        }: ZoneAnchorRecord,
    ) -> Self {
        Self {
            slot,
            block_id,
            hash,
        }
    }
}

impl From<db_cells::ZoneAnchorRecord> for ZoneAnchorRecord {
    fn from(
        db_cells::ZoneAnchorRecord {
            slot,
            block_id,
            hash,
        }: db_cells::ZoneAnchorRecord,
    ) -> Self {
        Self {
            slot,
            block_id,
            hash,
        }
    }
}

/// An L1 deposit event observed but not yet seen finalized.
///
/// Purely a liveness queue: whether to emit a mint is decided against chain
/// state, and the record is dropped once its mint finalizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDepositEventRecord {
    pub deposit_op_id: HashType,
    pub source_tx_hash: HashType,
    pub amount: u64,
    pub metadata: Vec<u8>,
}

impl From<PendingDepositEventRecord> for db_cells::PendingDepositEventRecord {
    fn from(
        PendingDepositEventRecord {
            deposit_op_id,
            source_tx_hash,
            amount,
            metadata,
        }: PendingDepositEventRecord,
    ) -> Self {
        Self {
            deposit_op_id,
            source_tx_hash,
            amount,
            metadata,
        }
    }
}

impl From<db_cells::PendingDepositEventRecord> for PendingDepositEventRecord {
    fn from(
        db_cells::PendingDepositEventRecord {
            deposit_op_id,
            source_tx_hash,
            amount,
            metadata,
        }: db_cells::PendingDepositEventRecord,
    ) -> Self {
        Self {
            deposit_op_id,
            source_tx_hash,
            amount,
            metadata,
        }
    }
}

/// A cross-zone delivery read off a peer block but not yet known to be
/// irreversibly delivered.
///
/// The watcher's delivery floor is durable, so once it advances past a peer
/// block that block is never re-read; this record stands in its place. It
/// carries no "submitted" mark: it is dropped when the delivery finalizes, and
/// re-including one meanwhile is harmless because the inbox no-ops a replay on
/// chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCrossZoneDispatchRecord {
    /// Content-addressed replay key of the delivered message, and this record's
    /// identity.
    pub message_key: [u8; 32],
    /// The borsh-encoded dispatch transaction, so production can re-feed it
    /// without re-reading the peer channel.
    pub transaction: Vec<u8>,
    /// Production attempts that ended in an execution failure. Past a threshold
    /// the record leaves this list for a [`DeadLetterDispatchRecord`].
    pub failed_attempts: u32,
}

impl PendingCrossZoneDispatchRecord {
    /// A delivery the watcher has just read: never attempted.
    #[must_use]
    pub const fn recorded(message_key: [u8; 32], transaction: Vec<u8>) -> Self {
        Self {
            message_key,
            transaction,
            failed_attempts: 0,
        }
    }
}

impl From<PendingCrossZoneDispatchRecord> for db_cells::PendingCrossZoneDispatchRecord {
    fn from(
        PendingCrossZoneDispatchRecord {
            message_key,
            transaction,
            failed_attempts,
        }: PendingCrossZoneDispatchRecord,
    ) -> Self {
        Self {
            message_key,
            transaction,
            failed_attempts,
        }
    }
}

impl From<db_cells::PendingCrossZoneDispatchRecord> for PendingCrossZoneDispatchRecord {
    fn from(
        db_cells::PendingCrossZoneDispatchRecord {
            message_key,
            transaction,
            failed_attempts,
        }: db_cells::PendingCrossZoneDispatchRecord,
    ) -> Self {
        Self {
            message_key,
            transaction,
            failed_attempts,
        }
    }
}

/// Which peer message a delivery carried, kept so a lost one can be traced back
/// to the peer block it was in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchOrigin {
    pub src_zone: PeerZoneKey,
    pub src_block_id: u64,
    pub src_tx_index: u32,
}

impl From<DispatchOrigin> for db_cells::DispatchOrigin {
    fn from(
        DispatchOrigin {
            src_zone,
            src_block_id,
            src_tx_index,
        }: DispatchOrigin,
    ) -> Self {
        Self {
            src_zone,
            src_block_id,
            src_tx_index,
        }
    }
}

impl From<db_cells::DispatchOrigin> for DispatchOrigin {
    fn from(
        db_cells::DispatchOrigin {
            src_zone,
            src_block_id,
            src_tx_index,
        }: db_cells::DispatchOrigin,
    ) -> Self {
        Self {
            src_zone,
            src_block_id,
            src_tx_index,
        }
    }
}

/// A cross-zone delivery this node has given up on.
///
/// A dispatch that fails execution is left out of the block, so nothing on
/// chain records that it was attempted; this is the only durable trace. It
/// carries the encoded transaction so a requeue can restore the delivery
/// without re-reading the peer channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetterDispatchRecord {
    pub message_key: [u8; 32],
    pub origin: DispatchOrigin,
    /// Attempts made before giving up, so the record carries the policy that was
    /// in force at the time.
    pub failed_attempts: u32,
    /// The borsh-encoded dispatch transaction. Its length is the diagnostic for
    /// size-related failures.
    pub transaction: Vec<u8>,
}

impl From<db_cells::DeadLetterDispatchRecord> for DeadLetterDispatchRecord {
    fn from(
        db_cells::DeadLetterDispatchRecord {
            message_key,
            origin,
            failed_attempts,
            transaction,
        }: db_cells::DeadLetterDispatchRecord,
    ) -> Self {
        Self {
            message_key,
            origin: origin.into(),
            failed_attempts,
            transaction,
        }
    }
}

/// What restoring a dead-lettered delivery did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadLetterRequeue {
    /// Moved back into the pending list with a clean attempt count.
    Requeued,
    /// The delivery was already pending again, so only the dead letter was
    /// dropped.
    AlreadyPending,
    /// No retained dead letter under that key.
    NotFound,
    /// Listed, but its transaction was over the retention bound and was not
    /// kept; the message must be read back off the peer channel instead.
    NotRetained,
}

impl From<db::DeadLetterRequeue> for DeadLetterRequeue {
    fn from(value: db::DeadLetterRequeue) -> Self {
        match value {
            db::DeadLetterRequeue::Requeued => Self::Requeued,
            db::DeadLetterRequeue::AlreadyPending => Self::AlreadyPending,
            db::DeadLetterRequeue::NotFound => Self::NotFound,
            db::DeadLetterRequeue::NotRetained => Self::NotRetained,
        }
    }
}

/// What counting a failed production attempt did to a delivery's record, the
/// reply to [`RecordDispatchFailure`].
///
/// Three outcomes rather than a bool: only one means this node stopped trying,
/// and a settled delivery has no record, so it is [`Self::Absent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchFailure {
    /// Counted; the delivery is still pending and will be attempted again.
    Retried { failed_attempts: u32 },
    /// Given up on: moved out of the pending list and into the dead letter.
    Retired(Box<DeadLetterDispatchRecord>),
    /// No pending record, so nothing was counted and nothing was given up on.
    Absent,
}

impl From<db::DispatchFailure> for DispatchFailure {
    fn from(value: db::DispatchFailure) -> Self {
        match value {
            db::DispatchFailure::Retried { failed_attempts } => Self::Retried { failed_attempts },
            db::DispatchFailure::Retired(record) => Self::Retired(Box::new((*record).into())),
            db::DispatchFailure::Absent => Self::Absent,
        }
    }
}

/// What [`ApplyStoreUpdate`] observed while staging, for the caller to act on
/// *after* the write committed.
#[derive(Debug, Default)]
pub struct StoreUpdateOutcome {
    /// How many deposit events were newly recorded; the rest were already
    /// pending, and so already owed.
    pub accepted_deposits: usize,
    /// Withdraw events with no matching local unseen counter, one entry per
    /// unmatched occurrence.
    pub unmatched_withdrawals: Vec<WithdrawalReconciliationKey>,
}

impl From<db::StoreUpdateOutcome> for StoreUpdateOutcome {
    fn from(
        db::StoreUpdateOutcome {
            accepted_deposits,
            unmatched_withdrawals,
        }: db::StoreUpdateOutcome,
    ) -> Self {
        Self {
            accepted_deposits,
            unmatched_withdrawals: unmatched_withdrawals.into_iter().map(Into::into).collect(),
        }
    }
}

/// Schema-agnostic snapshot of a whole store, opaque by design.
pub struct DbDump(db::DbDump);

impl DbDump {
    /// Serializes the dump to a compressed blob.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.0.to_bytes().map_err(Into::into)
    }

    /// Reads back a dump produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        db::DbDump::from_bytes(bytes).map(Self).map_err(Into::into)
    }

    /// The wrapped dump, for the restore path.
    pub(crate) const fn as_db_dump(&self) -> &db::DbDump {
        &self.0
    }
}

impl From<db::DbDump> for DbDump {
    fn from(value: db::DbDump) -> Self {
        Self(value)
    }
}
