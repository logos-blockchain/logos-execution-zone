use borsh::{BorshDeserialize, BorshSerialize};
pub use common::block::PeerChainTip;
use common::{HashType, block::BlockMeta};
use lee::V03State;

use crate::{
    CF_META_NAME, DbResult,
    cells::{SimpleReadableCell, SimpleStorableCell, SimpleWritableCell},
    error::DbError,
    sequencer::{
        CF_LEE_STATE_NAME, DB_FINAL_BLOCK_META_KEY, DB_FINAL_LEE_STATE_KEY, DB_LEE_STATE_KEY,
        DB_META_CHANNEL_CURSOR_KEY, DB_META_CROSS_ZONE_PEER_FLOOR_KEY,
        DB_META_CROSS_ZONE_PEER_TIP_KEY, DB_META_DEAD_LETTER_CROSS_ZONE_DISPATCH_COUNT_KEY,
        DB_META_DEAD_LETTER_CROSS_ZONE_DISPATCHES_KEY, DB_META_LAST_FINALIZED_BLOCK_ID,
        DB_META_LATEST_BLOCK_META_KEY, DB_META_PENDING_CROSS_ZONE_DISPATCH_COUNT_KEY,
        DB_META_PENDING_CROSS_ZONE_DISPATCH_KEY, DB_META_PENDING_CROSS_ZONE_DISPATCHES_KEY,
        DB_META_PENDING_DEPOSIT_EVENTS_KEY, DB_META_PUBLISHED_HIGH_WATER_KEY,
        DB_META_SLASH_RECORD_KEY, DB_META_UNSEEN_WITHDRAW_COUNT_KEY, DB_META_ZONE_CURSOR_KEY,
        DB_META_ZONE_SDK_CHECKPOINT_KEY,
    },
};

#[derive(BorshDeserialize)]
pub struct LEEStateCellOwned(pub V03State);

impl SimpleStorableCell for LEEStateCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_LEE_STATE_KEY;
    const CF_NAME: &'static str = CF_LEE_STATE_NAME;
}

impl SimpleReadableCell for LEEStateCellOwned {}

#[derive(BorshSerialize)]
pub struct LEEStateCellRef<'state>(pub &'state V03State);

impl SimpleStorableCell for LEEStateCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_LEE_STATE_KEY;
    const CF_NAME: &'static str = CF_LEE_STATE_NAME;
}

impl SimpleWritableCell for LEEStateCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize last state".to_owned()))
        })
    }
}

/// State at the last L1-finalized block, written atomically with
/// [`FinalBlockMetaCellRef`].
#[derive(BorshDeserialize)]
pub struct FinalLeeStateCellOwned(pub V03State);

impl SimpleStorableCell for FinalLeeStateCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_FINAL_LEE_STATE_KEY;
    const CF_NAME: &'static str = CF_LEE_STATE_NAME;
}

impl SimpleReadableCell for FinalLeeStateCellOwned {}

#[derive(BorshSerialize)]
pub struct FinalLeeStateCellRef<'state>(pub &'state V03State);

impl SimpleStorableCell for FinalLeeStateCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_FINAL_LEE_STATE_KEY;
    const CF_NAME: &'static str = CF_LEE_STATE_NAME;
}

impl SimpleWritableCell for FinalLeeStateCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize final state".to_owned()))
        })
    }
}

/// `(id, hash)` of the last L1-finalized block, paired with [`FinalLeeStateCellRef`].
#[derive(BorshDeserialize)]
pub struct FinalBlockMetaCellOwned(pub BlockMeta);

impl SimpleStorableCell for FinalBlockMetaCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_FINAL_BLOCK_META_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for FinalBlockMetaCellOwned {}

#[derive(BorshSerialize)]
pub struct FinalBlockMetaCellRef<'blockmeta>(pub &'blockmeta BlockMeta);

impl SimpleStorableCell for FinalBlockMetaCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_FINAL_BLOCK_META_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleWritableCell for FinalBlockMetaCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize final block meta".to_owned()),
            )
        })
    }
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct LastFinalizedBlockIdCell(pub Option<u64>);

impl SimpleStorableCell for LastFinalizedBlockIdCell {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_LAST_FINALIZED_BLOCK_ID;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for LastFinalizedBlockIdCell {}

impl SimpleWritableCell for LastFinalizedBlockIdCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize last finalized block id".to_owned()),
            )
        })
    }
}

/// The highest block id this sequencer must not inscribe on the channel again.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct PublishedHighWaterCell(pub u64);

impl SimpleStorableCell for PublishedHighWaterCell {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_PUBLISHED_HIGH_WATER_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for PublishedHighWaterCell {}

impl SimpleWritableCell for PublishedHighWaterCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize published high water mark".to_owned()),
            )
        })
    }
}

/// The `MsgId` of the newest channel inscription processed, block or not —
/// the parent the next produced block is pinned on.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct ChannelCursorCell(pub [u8; 32]);

impl SimpleStorableCell for ChannelCursorCell {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_CHANNEL_CURSOR_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for ChannelCursorCell {}

impl SimpleWritableCell for ChannelCursorCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize channel cursor".to_owned()))
        })
    }
}

#[derive(BorshDeserialize)]
pub struct LatestBlockMetaCellOwned(pub BlockMeta);

impl SimpleStorableCell for LatestBlockMetaCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_LATEST_BLOCK_META_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for LatestBlockMetaCellOwned {}

#[derive(BorshSerialize)]
pub struct LatestBlockMetaCellRef<'blockmeta>(pub &'blockmeta BlockMeta);

impl SimpleStorableCell for LatestBlockMetaCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_LATEST_BLOCK_META_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleWritableCell for LatestBlockMetaCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize last block meta".to_owned()))
        })
    }
}

/// Opaque bytes for the zone-sdk sequencer checkpoint. The caller is
/// responsible for the actual encoding (we use `serde_json` since
/// `SequencerCheckpoint` only derives serde, not borsh).
#[derive(BorshDeserialize)]
pub struct ZoneSdkCheckpointCellOwned(pub Vec<u8>);

impl SimpleStorableCell for ZoneSdkCheckpointCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_ZONE_SDK_CHECKPOINT_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for ZoneSdkCheckpointCellOwned {}

#[derive(BorshSerialize)]
pub struct ZoneSdkCheckpointCellRef<'bytes>(pub &'bytes [u8]);

impl SimpleStorableCell for ZoneSdkCheckpointCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_ZONE_SDK_CHECKPOINT_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleWritableCell for ZoneSdkCheckpointCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize zone-sdk checkpoint cell".to_owned()),
            )
        })
    }
}

/// The slashing record as opaque bytes. `sequencer_core` owns the encoding.
#[derive(BorshDeserialize)]
pub struct SlashRecordCellOwned(pub Vec<u8>);

impl SimpleStorableCell for SlashRecordCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_SLASH_RECORD_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for SlashRecordCellOwned {}

#[derive(BorshSerialize)]
pub struct SlashRecordCellRef<'bytes>(pub &'bytes [u8]);

impl SimpleStorableCell for SlashRecordCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_SLASH_RECORD_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleWritableCell for SlashRecordCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize slash record cell".to_owned()),
            )
        })
    }
}

/// The last channel block read back and verified from Bedrock.
///
/// Holds its L1 inscription `slot` plus the block's `id`/`hash`, and serves as
/// both the anchor for the startup consistency check and the resume point for
/// reconstruction. `slot` is stored as a raw `u64` because the zone-sdk `Slot`
/// does not derive borsh; the caller converts to/from `Slot`.
#[derive(Debug, Clone, Copy, BorshSerialize, BorshDeserialize)]
pub struct ZoneAnchorRecord {
    pub slot: u64,
    pub block_id: u64,
    pub hash: HashType,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct ZoneAnchorCell(pub ZoneAnchorRecord);

impl SimpleStorableCell for ZoneAnchorCell {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_ZONE_CURSOR_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for ZoneAnchorCell {}

impl SimpleWritableCell for ZoneAnchorCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize zone cursor".to_owned()))
        })
    }
}

/// An L1 deposit event observed but not yet seen finalized.
///
/// Purely a liveness queue: whether to actually emit a mint is decided against
/// chain state (the deposit-receipt PDA), and the record is dropped once its
/// mint finalizes.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PendingDepositEventRecord {
    pub deposit_op_id: HashType,
    pub source_tx_hash: HashType,
    pub amount: u64,
    pub metadata: Vec<u8>,
}

/// A cross-zone delivery the watcher has read off a peer block but which is not
/// yet known to be irreversibly delivered.
///
/// The watcher's delivery floor is durable, so once it advances past a peer
/// block that block is never re-read. This record is what stands in its place:
/// block production drains it every turn, and it survives a restart. Mirrors
/// [`PendingDepositEventRecord`], which solves the same problem for deposits,
/// and like it carries no "submitted" mark: the record is dropped when the
/// delivery itself finalizes, and re-including one meanwhile is harmless
/// because the inbox no-ops a replay on chain.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PendingCrossZoneDispatchRecord {
    /// Content-addressed replay key of the delivered message, and this record's
    /// identity.
    pub message_key: [u8; 32],
    /// The borsh-encoded dispatch transaction, so production can re-feed it
    /// without re-reading the peer channel.
    pub transaction: Vec<u8>,
    /// Production attempts that ended in an execution failure.
    ///
    /// A dispatch's payload and target accounts are chosen on the peer zone and
    /// validated by nobody in between, so one can fail for good. A failure can
    /// equally be a property of the moment, so a single one is not enough to
    /// give up on a delivery. Once too many accumulate the record leaves this
    /// list (the drain re-feeds it every turn) for a
    /// [`DeadLetterDispatchRecord`], which keeps the delivery identifiable.
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

/// One pending delivery, held under its own message key so a mutation touches
/// one entry rather than rewriting the whole set.
#[derive(BorshDeserialize)]
pub struct PendingCrossZoneDispatchCellOwned(pub PendingCrossZoneDispatchRecord);

impl SimpleStorableCell for PendingCrossZoneDispatchCellOwned {
    type KeyParams = [u8; 32];

    const CELL_NAME: &'static str = DB_META_PENDING_CROSS_ZONE_DISPATCH_KEY;
    const CF_NAME: &'static str = CF_META_NAME;

    /// Folds the message key into the db key so each delivery is its own entry.
    fn key_constructor(message_key: Self::KeyParams) -> DbResult<Vec<u8>> {
        borsh::to_vec(&(Self::CELL_NAME, message_key)).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some(format!(
                    "Failed to serialize {:?} key params",
                    Self::CELL_NAME
                )),
            )
        })
    }
}

impl SimpleReadableCell for PendingCrossZoneDispatchCellOwned {}

#[derive(BorshSerialize)]
pub struct PendingCrossZoneDispatchCellRef<'record>(pub &'record PendingCrossZoneDispatchRecord);

impl SimpleStorableCell for PendingCrossZoneDispatchCellRef<'_> {
    type KeyParams = [u8; 32];

    const CELL_NAME: &'static str = DB_META_PENDING_CROSS_ZONE_DISPATCH_KEY;
    const CF_NAME: &'static str = CF_META_NAME;

    fn key_constructor(message_key: Self::KeyParams) -> DbResult<Vec<u8>> {
        borsh::to_vec(&(Self::CELL_NAME, message_key)).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some(format!(
                    "Failed to serialize {:?} key params",
                    Self::CELL_NAME
                )),
            )
        })
    }
}

impl SimpleWritableCell for PendingCrossZoneDispatchCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize pending cross-zone dispatch cell".to_owned()),
            )
        })
    }
}

/// How many pending dispatch records the store holds, written in the same
/// batch as every record mutation so the cap check reads one value instead of
/// scanning the set it bounds.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct PendingCrossZoneDispatchCountCell(pub u64);

impl SimpleStorableCell for PendingCrossZoneDispatchCountCell {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_PENDING_CROSS_ZONE_DISPATCH_COUNT_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for PendingCrossZoneDispatchCountCell {}

impl SimpleWritableCell for PendingCrossZoneDispatchCountCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize pending cross-zone dispatch count".to_owned()),
            )
        })
    }
}

/// The whole pending set as one borsh blob, the layout stores held before the
/// per-message entries. Read-only: opening such a store migrates the blob and
/// deletes its key, and nothing writes it again.
#[derive(BorshDeserialize)]
pub struct LegacyPendingCrossZoneDispatchesCellOwned(pub Vec<PendingCrossZoneDispatchRecord>);

impl SimpleStorableCell for LegacyPendingCrossZoneDispatchesCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_PENDING_CROSS_ZONE_DISPATCHES_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for LegacyPendingCrossZoneDispatchesCellOwned {}

/// Which peer message a delivery carried, kept so a lost one can be traced back
/// to the peer block it was in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DispatchOrigin {
    pub src_zone: PeerZoneKey,
    pub src_block_id: u64,
    pub src_tx_index: u32,
}

/// A cross-zone delivery this node has given up on.
///
/// A dispatch that fails execution is left out of the block, so nothing on chain
/// records that it was attempted; this is the only durable trace.
///
/// It carries the encoded transaction, not just its size: a requeue has to
/// restore the delivery without re-reading the peer channel, and the retained
/// list is bounded to far fewer entries than the pending list that held the
/// same bytes moments before.
///
/// Giving up is this node's decision, not the network's, so an entry is dropped
/// again if another sequencer carries the same delivery.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DeadLetterDispatchRecord {
    pub message_key: [u8; 32],
    pub origin: DispatchOrigin,
    /// Attempts made before giving up, so the record carries the policy that was
    /// in force at the time.
    pub failed_attempts: u32,
    /// The borsh-encoded dispatch transaction, kept so a requeue can restore
    /// the delivery. Its length is the diagnostic for size-related failures.
    pub transaction: Vec<u8>,
}

#[derive(BorshDeserialize)]
pub struct DeadLetterCrossZoneDispatchesCellOwned(pub Vec<DeadLetterDispatchRecord>);

impl SimpleStorableCell for DeadLetterCrossZoneDispatchesCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_DEAD_LETTER_CROSS_ZONE_DISPATCHES_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for DeadLetterCrossZoneDispatchesCellOwned {}

#[derive(BorshSerialize)]
pub struct DeadLetterCrossZoneDispatchesCellRef<'records>(pub &'records [DeadLetterDispatchRecord]);

impl SimpleStorableCell for DeadLetterCrossZoneDispatchesCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_DEAD_LETTER_CROSS_ZONE_DISPATCHES_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleWritableCell for DeadLetterCrossZoneDispatchesCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize dead-letter cross-zone dispatches cell".to_owned()),
            )
        })
    }
}

/// Deliveries given up on since this store was created.
///
/// Separate from the retained list, which evicts at its cap and drops settled
/// entries: a node that gave up hundreds of times would otherwise look like one
/// that gave up at the cap.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct DeadLetterCrossZoneDispatchCountCell(pub u64);

impl SimpleStorableCell for DeadLetterCrossZoneDispatchCountCell {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_DEAD_LETTER_CROSS_ZONE_DISPATCH_COUNT_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for DeadLetterCrossZoneDispatchCountCell {}

impl SimpleWritableCell for DeadLetterCrossZoneDispatchCountCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize dead-letter cross-zone dispatch count".to_owned()),
            )
        })
    }
}

#[derive(BorshDeserialize)]
pub struct PendingDepositEventsCellOwned(pub Vec<PendingDepositEventRecord>);

impl SimpleStorableCell for PendingDepositEventsCellOwned {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_PENDING_DEPOSIT_EVENTS_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleReadableCell for PendingDepositEventsCellOwned {}

#[derive(BorshSerialize)]
pub struct PendingDepositEventsCellRef<'records>(pub &'records [PendingDepositEventRecord]);

impl SimpleStorableCell for PendingDepositEventsCellRef<'_> {
    type KeyParams = ();

    const CELL_NAME: &'static str = DB_META_PENDING_DEPOSIT_EVENTS_KEY;
    const CF_NAME: &'static str = CF_META_NAME;
}

impl SimpleWritableCell for PendingDepositEventsCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize pending deposit events cell".to_owned()),
            )
        })
    }
}

/// Identifies which peer channel a cross-zone watcher cursor belongs to. The
/// 32-byte peer channel id doubles as the peer's zone id.
pub type PeerZoneKey = [u8; 32];

/// Opaque bytes for one peer's cross-zone read cursor. As with the zone-sdk
/// checkpoint, the caller owns the encoding, since the cursor type derives serde
/// rather than borsh.
#[derive(BorshDeserialize)]
pub struct PeerFloorCellOwned(pub Vec<u8>);

impl SimpleStorableCell for PeerFloorCellOwned {
    type KeyParams = PeerZoneKey;

    const CELL_NAME: &'static str = DB_META_CROSS_ZONE_PEER_FLOOR_KEY;
    const CF_NAME: &'static str = CF_META_NAME;

    /// Folds the peer zone into the key so each peer keeps its own cursor.
    fn key_constructor(peer_zone: Self::KeyParams) -> DbResult<Vec<u8>> {
        borsh::to_vec(&(Self::CELL_NAME, peer_zone)).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some(format!(
                    "Failed to serialize {:?} key params",
                    Self::CELL_NAME
                )),
            )
        })
    }
}

impl SimpleReadableCell for PeerFloorCellOwned {}

#[derive(BorshSerialize)]
pub struct PeerFloorCellRef<'bytes>(pub &'bytes [u8]);

impl SimpleStorableCell for PeerFloorCellRef<'_> {
    type KeyParams = PeerZoneKey;

    const CELL_NAME: &'static str = DB_META_CROSS_ZONE_PEER_FLOOR_KEY;
    const CF_NAME: &'static str = CF_META_NAME;

    /// Folds the peer zone into the key so each peer keeps its own cursor.
    fn key_constructor(peer_zone: Self::KeyParams) -> DbResult<Vec<u8>> {
        borsh::to_vec(&(Self::CELL_NAME, peer_zone)).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some(format!(
                    "Failed to serialize {:?} key params",
                    Self::CELL_NAME
                )),
            )
        })
    }
}

impl SimpleWritableCell for PeerFloorCellRef<'_> {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize cross-zone peer floor cell".to_owned()),
            )
        })
    }
}

/// The watcher's [`PeerChainTip`], durable rather than in-memory: a watcher
/// that re-anchored on restart would accept a block claiming any id.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct PeerTipCell(pub PeerChainTip);

impl SimpleStorableCell for PeerTipCell {
    type KeyParams = PeerZoneKey;

    const CELL_NAME: &'static str = DB_META_CROSS_ZONE_PEER_TIP_KEY;
    const CF_NAME: &'static str = CF_META_NAME;

    /// Folds the peer zone into the key so each peer keeps its own tip.
    fn key_constructor(peer_zone: Self::KeyParams) -> DbResult<Vec<u8>> {
        borsh::to_vec(&(Self::CELL_NAME, peer_zone)).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some(format!(
                    "Failed to serialize {:?} key params",
                    Self::CELL_NAME
                )),
            )
        })
    }
}

impl SimpleReadableCell for PeerTipCell {}

impl SimpleWritableCell for PeerTipCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize cross-zone peer tip cell".to_owned()),
            )
        })
    }
}

/// Identity of one withdrawal, shared by the intent recorded when the
/// sequencer publishes it and the Bedrock Withdraw event that later reports
/// it: the id of the channel note the withdrawal releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WithdrawalReconciliationKey {
    pub released_note_id: [u8; 32],
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct UnseenWithdrawCountCell(pub u64);

impl SimpleStorableCell for UnseenWithdrawCountCell {
    type KeyParams = WithdrawalReconciliationKey;

    const CELL_NAME: &'static str = DB_META_UNSEEN_WITHDRAW_COUNT_KEY;
    const CF_NAME: &'static str = CF_META_NAME;

    fn key_constructor(key_params: Self::KeyParams) -> DbResult<Vec<u8>> {
        let WithdrawalReconciliationKey { released_note_id } = key_params;

        borsh::to_vec(&(Self::CELL_NAME, released_note_id)).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some(format!(
                    "Failed to serialize {:?} key params",
                    Self::CELL_NAME
                )),
            )
        })
    }
}

impl SimpleReadableCell for UnseenWithdrawCountCell {}

impl SimpleWritableCell for UnseenWithdrawCountCell {
    fn value_constructor(&self) -> DbResult<Vec<u8>> {
        borsh::to_vec(&self).map_err(|err| {
            DbError::borsh_cast_message(
                err,
                Some("Failed to serialize unseen withdraw count".to_owned()),
            )
        })
    }
}

#[cfg(test)]
mod uniform_tests {
    use crate::{
        cells::SimpleStorableCell as _,
        sequencer::sequencer_cells::{
            LEEStateCellOwned, LEEStateCellRef, LatestBlockMetaCellOwned, LatestBlockMetaCellRef,
            LegacyPendingCrossZoneDispatchesCellOwned, PendingCrossZoneDispatchCellOwned,
            PendingCrossZoneDispatchCellRef, PendingCrossZoneDispatchCountCell,
            PendingDepositEventsCellOwned, PendingDepositEventsCellRef,
        },
    };

    #[test]
    fn state_ref_and_owned_is_aligned() {
        assert_eq!(LEEStateCellRef::CELL_NAME, LEEStateCellOwned::CELL_NAME);
        assert_eq!(LEEStateCellRef::CF_NAME, LEEStateCellOwned::CF_NAME);
        assert_eq!(
            LEEStateCellRef::key_constructor(()).unwrap(),
            LEEStateCellOwned::key_constructor(()).unwrap()
        );
    }

    #[test]
    fn block_meta_ref_and_owned_is_aligned() {
        assert_eq!(
            LatestBlockMetaCellRef::CELL_NAME,
            LatestBlockMetaCellOwned::CELL_NAME
        );
        assert_eq!(
            LatestBlockMetaCellRef::CF_NAME,
            LatestBlockMetaCellOwned::CF_NAME
        );
        assert_eq!(
            LatestBlockMetaCellRef::key_constructor(()).unwrap(),
            LatestBlockMetaCellOwned::key_constructor(()).unwrap()
        );
    }

    #[test]
    fn pending_dispatch_ref_and_owned_is_aligned() {
        assert_eq!(
            PendingCrossZoneDispatchCellRef::CELL_NAME,
            PendingCrossZoneDispatchCellOwned::CELL_NAME
        );
        assert_eq!(
            PendingCrossZoneDispatchCellRef::CF_NAME,
            PendingCrossZoneDispatchCellOwned::CF_NAME
        );
        assert_eq!(
            PendingCrossZoneDispatchCellRef::key_constructor([7; 32]).unwrap(),
            PendingCrossZoneDispatchCellOwned::key_constructor([7; 32]).unwrap()
        );
    }

    #[test]
    fn pending_dispatch_scan_prefix_covers_only_the_per_message_cells() {
        // A stray meta cell keyed into this range would decode as a dispatch
        // record and fail the lock-free scan.
        let prefix = borsh::to_vec(&PendingCrossZoneDispatchCellOwned::CELL_NAME).unwrap();
        assert!(
            PendingCrossZoneDispatchCellOwned::key_constructor([0; 32])
                .unwrap()
                .starts_with(&prefix)
        );
        assert!(
            !PendingCrossZoneDispatchCountCell::key_constructor(())
                .unwrap()
                .starts_with(&prefix),
            "the count cell must stay out of the record scan"
        );
        assert!(
            !LegacyPendingCrossZoneDispatchesCellOwned::key_constructor(())
                .unwrap()
                .starts_with(&prefix),
            "the legacy blob must stay out of the record scan"
        );
    }

    #[test]
    fn pending_deposit_events_ref_and_owned_is_aligned() {
        assert_eq!(
            PendingDepositEventsCellRef::CELL_NAME,
            PendingDepositEventsCellOwned::CELL_NAME
        );
        assert_eq!(
            PendingDepositEventsCellRef::CF_NAME,
            PendingDepositEventsCellOwned::CF_NAME
        );
        assert_eq!(
            PendingDepositEventsCellRef::key_constructor(()).unwrap(),
            PendingDepositEventsCellOwned::key_constructor(()).unwrap()
        );
    }
}
