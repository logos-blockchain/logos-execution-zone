use std::{collections::HashSet, sync::Arc};

use common::{
    HashType,
    block::{Block, BlockMeta, PeerChainTip},
};
use lee::V03State;
use lee_core::BlockId;

/// Content-addressed replay key of a cross-zone message, and the identity of the
/// records tracking its delivery.
pub type CrossZoneMessageKey = [u8; 32];

/// Zone id of a cross-zone peer.
pub type PeerZoneKey = [u8; 32];

/// The zone-sdk `MsgId` of a channel inscription, as the raw bytes it wraps: the
/// sdk type does not derive borsh, and so cannot be stored.
pub type MsgId = [u8; 32];

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

pub struct ResetAllBlocksToPending;

pub struct GetFirstBlockId;

pub struct GetLastBlockId;

pub struct GetLatestBlockMeta;

pub struct GetLeeState;

pub struct GetZoneCheckpointBytes;

pub struct SetZoneCheckpointBytes {
    // TODO: Consider `bytes` crate for all `Vec<u8>` in protocol.
    pub bytes: Vec<u8>,
}

pub struct DeleteZoneCheckpoint;

pub struct GetSlashRecordBytes;

pub struct PutSlashRecordBytes {
    pub bytes: Vec<u8>,
}

pub struct GetZoneAnchor;

pub struct SetZoneAnchor {
    pub anchor: ZoneAnchorRecord,
}

pub struct GetPublishedHighWater;

/// The `MsgId` of the newest channel inscription processed, block or not.
pub struct GetChannelCursor;

/// Raises the published high water mark to `block_id`, never lowering it.
pub struct RaisePublishedHighWater {
    pub block_id: BlockId,
}

pub struct GetPendingDepositEvents;

pub struct GetFinalSnapshot;

pub struct GetPendingCrossZoneDispatches;

pub struct AddPendingCrossZoneDispatches {
    pub dispatches: Vec<PendingCrossZoneDispatchRecord>,
}

pub struct DropSettledCrossZoneDispatches {
    pub message_keys: HashSet<CrossZoneMessageKey>,
}

pub struct RecordDispatchFailure {
    pub message_key: CrossZoneMessageKey,
    pub retire_at: u32,
    pub origin: DispatchOrigin,
}

pub struct GetDeadLetterDispatches;

/// Restores a retained dead-lettered delivery to the pending list, with a clean
/// attempt count.
pub struct RequeueDeadLetterDispatch {
    pub message_key: CrossZoneMessageKey,
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

/// Update everything in the store at once, atomically.
pub struct AtomicUpdate {
    /// Serialized zone-sdk checkpoint for this event.
    pub checkpoint: Option<Vec<u8>>,

    /// Block payloads to write.
    pub blocks: Vec<Block>,

    /// The `MsgId` of the newest inscription this update processed, block or
    /// not; `None` leaves the stored cursor untouched.
    pub channel_cursor: Option<MsgId>,

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
    pub finalized_deposit_records: HashSet<HashType>,
    /// L1 withdraw events to reconcile against the intents held locally.
    pub consumed_withdrawals: HashSet<WithdrawalReconciliationKey>,
    /// L2 withdraw intents this update raises, awaiting their L1 event.
    pub new_withdraw_intents: HashSet<WithdrawalReconciliationKey>,

    /// Message keys whose delivery finalized: their pending records are dropped.
    pub finalized_dispatch_records: HashSet<CrossZoneMessageKey>,

    /// Advance the channel-read anchor.
    pub zone_anchor: Option<ZoneAnchorRecord>,

    /// Lower the published high water mark to this height if it is above.
    pub lower_published_high_water: Option<BlockId>,
}

impl AtomicUpdate {
    /// Create [`ApplyStoreUpdate`] from a single non-finalized block and state.
    ///
    /// Leaves all other fields empty or [`None`].
    #[must_use]
    pub fn from_block(block: Block, state: Arc<V03State>) -> Self {
        Self {
            checkpoint: None,
            head_tip: Some(BlockMeta::from(&block)),
            blocks: vec![block],
            channel_cursor: None,
            head_state: state,
            final_snapshot: None,
            finalized_up_to: None,
            new_deposit_events: Vec::new(),
            finalized_deposit_records: HashSet::new(),
            finalized_dispatch_records: HashSet::new(),
            consumed_withdrawals: HashSet::new(),
            new_withdraw_intents: HashSet::new(),
            zone_anchor: None,
            lower_published_high_water: None,
        }
    }
}

/// Identity of one withdrawal: the id of the channel note it releases.
///
/// Shared by the intent recorded when the sequencer publishes a withdrawal and
/// the Bedrock event that later reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WithdrawalReconciliationKey {
    pub released_note_id: [u8; 32],
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
    pub message_key: CrossZoneMessageKey,
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
    pub const fn recorded(message_key: CrossZoneMessageKey, transaction: Vec<u8>) -> Self {
        Self {
            message_key,
            transaction,
            failed_attempts: 0,
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

/// A cross-zone delivery this node has given up on.
///
/// A dispatch that fails execution is left out of the block, so nothing on
/// chain records that it was attempted; this is the only durable trace. It
/// carries the encoded transaction so a requeue can restore the delivery
/// without re-reading the peer channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetterDispatch {
    pub message_key: CrossZoneMessageKey,
    pub origin: DispatchOrigin,
    /// Attempts made before giving up, so the record carries the policy that was
    /// in force at the time.
    pub failed_attempts: u32,
    /// The borsh-encoded dispatch transaction. Its length is the diagnostic for
    /// size-related failures.
    pub transaction: Vec<u8>,
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

/// What counting a failed production attempt did to a delivery's record, the
/// reply to [`RecordDispatchFailure`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchFailure {
    /// Counted; the delivery is still pending and will be attempted again.
    Retried { failed_attempts: u32 },
    /// Given up on: moved out of the pending list and into the dead letter.
    Retired(Box<DeadLetterDispatch>),
    /// No pending record, so nothing was counted and nothing was given up on.
    Absent,
}

/// What [`ApplyStoreUpdate`] observed while staging, for the caller to act on
/// *after* the write committed.
#[derive(Debug, Default)]
pub struct StoreUpdateOutcome {
    /// How many deposit events were newly recorded; the rest were already
    /// pending, and so already owed.
    pub accepted_deposits: usize,
    /// The `consumed_withdrawals` this node holds no intent for: a released
    /// note it never published, and so cannot account for.
    pub unmatched_withdrawals: Vec<WithdrawalReconciliationKey>,
}

/// Schema-agnostic snapshot of a whole store, opaque by design.
pub struct DbDump {
    pub bytes: Vec<u8>,
}
