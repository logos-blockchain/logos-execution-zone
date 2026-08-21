use borsh::{BorshDeserialize, BorshSerialize};
use common::{
    HashType,
    block::{BlockMeta, PeerChainTip},
};
use lee_core::BlockId;

use crate::actor::{
    db,
    encoding::{BigEndian, BorshArc, SingletonKey},
};

/// Memtable size for the families holding small records, well above
/// what they take between flushes.
const SMALL_WRITE_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Values above this are large enough to be worth keeping out of the
/// LSM tree.
const MIN_BLOB_SIZE: u64 = 4 * 1024;

/// Content-addressed replay key of a cross-zone message, and the identity of
/// the records tracking its delivery.
pub type CrossZoneMessageKey = [u8; 32];

/// Zone id of a cross-zone peer, which doubles as the id of its channel.
pub type PeerZoneKey = [u8; 32];

/// The zone-sdk `MsgId` of a channel inscription, as the raw bytes it wraps.
pub type MsgId = [u8; 32];

/// Families group entities by how they are written, not by what they mean:
/// types sharing one are still stored under disjoint keys.
#[derive(strum::IntoStaticStr, enum_iterator::Sequence)]
pub enum ColumnFamily {
    /// Many medium-sized records, appended and scanned in key order.
    Block,
    /// A handful of large values, rewritten on every store update.
    State,
    /// Small records that live as long as the database.
    Meta,
    /// Small records deleted as the work they track settles.
    Pending,
}

impl db::ColumnFamilies for ColumnFamily {
    fn options(&self) -> rocksdb::Options {
        let mut options = rocksdb::Options::default();

        match *self {
            Self::Block => {
                // Written in bursts of whole blocks, so more memtables to fill
                // while one flushes.
                options.set_max_write_buffer_number(4);
            }
            Self::State => {
                // A whole state is rewritten on every update. Blob files keep
                // those values out of compaction, which would otherwise copy
                // every one of them through each level.
                options.set_enable_blob_files(true);
                options.set_min_blob_size(MIN_BLOB_SIZE);
                options.set_enable_blob_gc(true);
            }
            Self::Meta | Self::Pending => {
                options.set_write_buffer_size(SMALL_WRITE_BUFFER_SIZE);
            }
        }

        options
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Block {
    pub block: common::block::Block,
}

impl db::Storable<ColumnFamily> for Block {
    type Key = BigEndian<BlockId>;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Block;
    const TYPE_NAME: &'static str = db::type_name!(Block);
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct LeeState {
    pub state: BorshArc<lee::V03State>,
}

impl db::Storable<ColumnFamily> for LeeState {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::State;
    const TYPE_NAME: &'static str = db::type_name!(LeeState);
}

/// State and `(id, hash)` at the last L1-finalized block.
///
/// One entity rather than two, so the pair can never disagree about which block
/// the state belongs to.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct FinalSnapshot {
    pub state: BorshArc<lee::V03State>,
    pub meta: BlockMeta,
}

impl db::Storable<ColumnFamily> for FinalSnapshot {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::State;
    const TYPE_NAME: &'static str = db::type_name!(FinalSnapshot);
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ZoneCheckpoint {
    pub bytes: Vec<u8>,
}

impl db::Storable<ColumnFamily> for ZoneCheckpoint {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Meta;
    const TYPE_NAME: &'static str = db::type_name!(ZoneCheckpoint);
}

/// The slashing record as opaque bytes, whose encoding the caller owns.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct SlashRecord {
    pub bytes: Vec<u8>,
}

impl db::Storable<ColumnFamily> for SlashRecord {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Meta;
    const TYPE_NAME: &'static str = db::type_name!(SlashRecord);
}

/// The last channel block read back and verified from Bedrock, with the L1
/// inscription slot it was found in.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct ZoneAnchor {
    pub slot: u64,
    pub block_id: BlockId,
    pub hash: HashType,
}

impl db::Storable<ColumnFamily> for ZoneAnchor {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Meta;
    const TYPE_NAME: &'static str = db::type_name!(ZoneAnchor);
}

/// The `MsgId` of the newest channel inscription processed, block or not: the
/// parent the next produced block is pinned on.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct ChannelCursor {
    pub msg_id: MsgId,
}

impl db::Storable<ColumnFamily> for ChannelCursor {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Meta;
    const TYPE_NAME: &'static str = db::type_name!(ChannelCursor);
}

/// The highest block id this sequencer must not inscribe on the channel again.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct PublishedHighWater {
    pub block_id: BlockId,
}

impl db::Storable<ColumnFamily> for PublishedHighWater {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Meta;
    const TYPE_NAME: &'static str = db::type_name!(PublishedHighWater);
}

/// An L1 deposit event observed but not yet seen finalized.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct PendingDeposit {
    pub deposit_op_id: HashType,
    pub source_tx_hash: HashType,
    pub amount: u64,
    pub metadata: Vec<u8>,
}

impl db::Storable<ColumnFamily> for PendingDeposit {
    type Key = HashType;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Pending;
    const TYPE_NAME: &'static str = db::type_name!(PendingDeposit);
}

/// Identity of one withdrawal: the id of the channel note it releases.
#[derive(Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct WithdrawalReconciliationKey {
    pub released_note_id: [u8; 32],
}

impl AsRef<[u8]> for WithdrawalReconciliationKey {
    fn as_ref(&self) -> &[u8] {
        &self.released_note_id
    }
}

/// An L2 withdraw intent this sequencer published, awaiting the Bedrock event
/// that reports it.
///
/// Carries no value: the key is the whole fact, and presence is the intent.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct PendingWithdrawal;

impl db::Storable<ColumnFamily> for PendingWithdrawal {
    type Key = WithdrawalReconciliationKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Pending;
    const TYPE_NAME: &'static str = db::type_name!(PendingWithdrawal);
}

/// A cross-zone delivery read off a peer block but not yet known to be
/// irreversibly delivered.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct PendingCrossZoneDispatch {
    pub message_key: CrossZoneMessageKey,
    pub transaction: Vec<u8>,
    pub failed_attempts: u32,
}

impl db::Storable<ColumnFamily> for PendingCrossZoneDispatch {
    type Key = CrossZoneMessageKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Pending;
    const TYPE_NAME: &'static str = db::type_name!(PendingCrossZoneDispatch);
}

/// The cross-zone deliveries this node has given up on.
///
/// One entity rather than a record per message: the retained list is ordered
/// and evicts at a cap, and `total` has to outlive the entries it counts.
#[derive(Default, BorshSerialize, BorshDeserialize)]
pub struct DeadLetterDispatches {
    /// Retained records, oldest first.
    pub records: Vec<DeadLetterDispatch>,
    /// Deliveries given up on since this database was created, including the
    /// ones since evicted from `records`.
    pub total: u64,
}

impl DeadLetterDispatches {
    // TODO: Remove this hardcoding unrelated to the storage actor and make it configurable by
    // the ExecutorActor (or CrossZoneRelayerActor in future).
    pub const MAX_DEAD_LETTER_CROSS_ZONE_DISPATCHES: usize = 256;

    pub fn push(&mut self, dispatch: DeadLetterDispatch) {
        if self
            .records
            .iter()
            .all(|record| record.message_key != dispatch.message_key)
        {
            self.records.push(dispatch);
            while self.records.len() > Self::MAX_DEAD_LETTER_CROSS_ZONE_DISPATCHES {
                self.records.remove(0);
            }
        }
        self.total = self.total.saturating_add(1);
    }

    /// Drops the retained record naming `message_key`, leaving [`Self::total`]
    /// alone: a delivery another sequencer carried is no longer worth retaining,
    /// but this node still gave up on it, and the count says how often that
    /// happened.
    pub fn remove(&mut self, message_key: &CrossZoneMessageKey) -> Option<DeadLetterDispatch> {
        let index = self
            .records
            .iter()
            .position(|record| &record.message_key == message_key)?;

        Some(self.records.remove(index))
    }
}

impl db::Storable<ColumnFamily> for DeadLetterDispatches {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Meta;
    const TYPE_NAME: &'static str = db::type_name!(DeadLetterDispatches);
}

/// One given-up-on delivery, carrying the transaction a requeue restores. The
/// peer block and index it names are the way back to a delivery whose bytes
/// were too large to retain.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct DeadLetterDispatch {
    pub message_key: CrossZoneMessageKey,
    pub origin: DispatchOrigin,
    pub failed_attempts: u32,
    /// [`None`] once the bytes were over [`Self::MAX_RETAINED_TRANSACTION_BYTES`].
    pub transaction: Option<Vec<u8>>,
}

impl DeadLetterDispatch {
    /// The largest transaction a dead letter retains for requeueing.
    pub const MAX_RETAINED_TRANSACTION_BYTES: usize = 64 * 1024;

    /// Gives up on `transaction`, retaining its bytes if they are small enough
    /// to be worth carrying in the list.
    pub fn retiring(
        message_key: CrossZoneMessageKey,
        origin: DispatchOrigin,
        failed_attempts: u32,
        transaction: Vec<u8>,
    ) -> Self {
        Self {
            message_key,
            origin,
            failed_attempts,
            transaction: (transaction.len() <= Self::MAX_RETAINED_TRANSACTION_BYTES)
                .then_some(transaction),
        }
    }
}

/// Which peer message a delivery carried.
#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
pub struct DispatchOrigin {
    pub zone: PeerZoneKey,
    pub block_id: BlockId,
    pub tx_index: u32,
}

/// One cross-zone watcher's delivery floor on a peer's channel, opaque here
/// because the caller owns its encoding.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct CrossZonePeerFloor {
    pub bytes: Vec<u8>,
}

impl db::Storable<ColumnFamily> for CrossZonePeerFloor {
    type Key = PeerZoneKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Meta;
    const TYPE_NAME: &'static str = db::type_name!(CrossZonePeerFloor);
}

/// The last peer block one cross-zone watcher delivered from.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct CrossZonePeerTip {
    pub tip: PeerChainTip,
}

impl db::Storable<ColumnFamily> for CrossZonePeerTip {
    type Key = PeerZoneKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::Meta;
    const TYPE_NAME: &'static str = db::type_name!(CrossZonePeerTip);
}
