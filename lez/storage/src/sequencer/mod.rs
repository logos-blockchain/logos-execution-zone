use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use borsh::{BorshDeserialize, BorshSerialize};
use common::{
    HashType,
    block::{BedrockStatus, Block, BlockMeta},
};
use lee::V03State;
use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, IteratorMode, MultiThreaded,
    Options, WriteBatch,
};

use crate::{
    CF_BLOCK_NAME, CF_META_NAME, DB_META_FIRST_BLOCK_IN_DB_KEY, DBIO, DbResult,
    cells::shared_cells::{BlockCell, FirstBlockCell, FirstBlockSetCell, LastBlockCell},
    error::DbError,
    sequencer::sequencer_cells::{
        FinalBlockMetaCellOwned, FinalBlockMetaCellRef, FinalLeeStateCellOwned,
        FinalLeeStateCellRef, LEEStateCellOwned, LEEStateCellRef, LastFinalizedBlockIdCell,
        LatestBlockMetaCellOwned, LatestBlockMetaCellRef, PeerChainTip, PeerFloorCellOwned,
        PeerFloorCellRef, PeerTipCell, PeerZoneKey, PendingCrossZoneDispatchRecord,
        PendingCrossZoneDispatchesCellOwned, PendingCrossZoneDispatchesCellRef,
        PendingDepositEventRecord, PendingDepositEventsCellOwned, PendingDepositEventsCellRef,
        PublishedHighWaterCell, UnseenWithdrawCountCell, WithdrawalReconciliationKey,
        ZoneAnchorCell, ZoneAnchorRecord, ZoneSdkCheckpointCellOwned, ZoneSdkCheckpointCellRef,
    },
};

pub mod sequencer_cells;

/// Key base for storing metainformation about the last finalized block on Bedrock.
pub const DB_META_LAST_FINALIZED_BLOCK_ID: &str = "last_finalized_block_id";
/// Key base for storing metainformation about the latest block meta.
pub const DB_META_LATEST_BLOCK_META_KEY: &str = "latest_block_meta";
/// Key base for storing the zone-sdk sequencer checkpoint (opaque bytes).
pub const DB_META_ZONE_SDK_CHECKPOINT_KEY: &str = "zone_sdk_checkpoint";
/// Key base for storing the last channel block read back and verified from
/// Bedrock (its L1 slot + `id`/`hash`) — the anchor for the startup
/// consistency check and the resume point for reconstruction.
pub const DB_META_ZONE_CURSOR_KEY: &str = "zone_cursor";
/// Key base for storing queued deposit events that were not yet
/// fulfilled on L2.
pub const DB_META_PENDING_DEPOSIT_EVENTS_KEY: &str = "pending_deposit_events";
/// Key base for storing a cross-zone watcher's delivery floor on one peer
/// channel (opaque bytes). Keyed per peer zone.
pub const DB_META_CROSS_ZONE_PEER_FLOOR_KEY: &str = "cross_zone_peer_floor";
/// Key base for storing the last peer block a cross-zone watcher delivered
/// from, as an id and hash pair. Keyed per peer zone.
pub const DB_META_CROSS_ZONE_PEER_TIP_KEY: &str = "cross_zone_peer_tip";
/// Key base for storing cross-zone deliveries the watcher has recorded but
/// which are not yet known to be irreversibly delivered.
pub const DB_META_PENDING_CROSS_ZONE_DISPATCHES_KEY: &str = "pending_cross_zone_dispatches";

/// Key base for counting unseen L2 withdraw intents.
pub const DB_META_UNSEEN_WITHDRAW_COUNT_KEY: &str = "unseen_withdraw_count";

/// Key base for the highest block id this sequencer has ever inscribed on the
/// channel. Never decreases, and deliberately survives the block pruning a
/// head rewind performs.
pub const DB_META_PUBLISHED_HIGH_WATER_KEY: &str = "published_high_water";

/// How many cross-zone deliveries may be pending at once.
///
/// The whole list is a single value, read on every block and rewritten on every
/// change, and what fills it is chosen by peer zones rather than by us. Refusing
/// to record past this bound turns "a peer decides how large our store gets"
/// into "a peer's messages wait", since a watcher that cannot record holds its
/// delivery floor and reads the slot again later.
pub const MAX_PENDING_CROSS_ZONE_DISPATCHES: usize = 4096;

/// Key base for storing the LEE state.
pub const DB_LEE_STATE_KEY: &str = "lee_state";
/// Key base for storing the LEE state at the last L1-finalized block.
pub const DB_FINAL_LEE_STATE_KEY: &str = "final_lee_state";
/// Key base for storing `(id, hash)` of the last L1-finalized block.
pub const DB_FINAL_BLOCK_META_KEY: &str = "final_block_meta";

/// Name of state column family.
pub const CF_LEE_STATE_NAME: &str = "cf_lee_state";

/// A single key/value entry from a column family, used inside [`DbDump`].
#[derive(BorshSerialize, BorshDeserialize)]
pub struct DbDumpEntry {
    pub cf_name: String,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// Schema-agnostic single-blob snapshot of a store: every key/value pair across all column
/// families. Lets a prebuilt store ship as one committed file instead of a rocksdb directory.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct DbDump {
    pub entries: Vec<DbDumpEntry>,
}

impl DbDump {
    /// Serialize the dump to a zstd-compressed borsh blob.
    pub fn to_bytes(&self) -> DbResult<Vec<u8>> {
        /// zstd compression level for [`DbDump::to_bytes`]. Level 19 keeps the committed fixture
        /// small without a meaningful decompression cost.
        const DUMP_ZSTD_LEVEL: i32 = 19;

        let borsh = borsh::to_vec(self).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize DbDump".to_owned()))
        })?;
        zstd::encode_all(borsh.as_slice(), DUMP_ZSTD_LEVEL).map_err(|err| {
            DbError::compression_error(err, Some("Failed to compress DbDump".to_owned()))
        })
    }

    /// Deserialize a dump produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> DbResult<Self> {
        let borsh = zstd::decode_all(bytes).map_err(|err| {
            DbError::db_interaction_error(format!("Failed to decompress DbDump: {err}"))
        })?;
        borsh::from_slice(&borsh).map_err(|err| {
            DbError::compression_error(err, Some("Failed to deserialize DbDump".to_owned()))
        })
    }
}

/// Everything one sequencer event writes, staged into a single [`WriteBatch`]
/// by [`RocksDBIO::store_update`].
///
/// The point of the struct is the `checkpoint`: it is the zone-sdk's resume
/// cursor, so it must land in the *same* write as the effects it covers.
/// Persisted ahead of them, a crash in between resumes the stream past blocks
/// that never reached the store — a gap the node cannot backfill.
pub struct StoreUpdate<'update> {
    /// Serialized zone-sdk checkpoint for this event.
    pub checkpoint: Option<&'update [u8]>,

    /// `(block, finalized)` payloads to write.
    pub blocks: &'update [(&'update Block, bool)],

    /// Head tip to pin the stored chain to; `None` only for an empty chain.
    pub head_tip: Option<&'update BlockMeta>,
    /// State after the last applied block.
    pub head_state: &'update V03State,

    /// `(state, meta)` of the final tier, when it advanced.
    pub final_snapshot: Option<(&'update V03State, &'update BlockMeta)>,
    /// Highest block id this event made irreversible: stored blocks at or below
    /// it become [`BedrockStatus::Finalized`].
    pub finalized_up_to: Option<u64>,

    /// Deposit events observed on L1, recorded unless already pending.
    pub new_deposit_events: &'update [PendingDepositEventRecord],
    /// Deposit op ids whose mint finalized: their pending records are dropped.
    pub remove_deposit_records: &'update [HashType],
    /// Message keys whose delivery finalized: their pending records are dropped.
    pub remove_dispatch_records: &'update [[u8; 32]],
    /// L1 withdraw events to reconcile against the local unseen counters.
    pub consumed_withdrawals: &'update [WithdrawalReconciliationKey],
    /// L2 withdraw intents this update raises, awaiting their L1 event.
    pub new_withdraw_intents: &'update [WithdrawalReconciliationKey],

    /// Advance the channel-read anchor.
    pub zone_anchor: Option<&'update ZoneAnchorRecord>,
}

impl<'update> StoreUpdate<'update> {
    /// An update that writes nothing but the caller's head `state`, to be
    /// filled in with `..StoreUpdate::new(state)`.
    #[must_use]
    pub const fn new(head_state: &'update V03State) -> Self {
        Self {
            checkpoint: None,
            blocks: &[],
            head_tip: None,
            head_state,
            final_snapshot: None,
            finalized_up_to: None,
            new_deposit_events: &[],
            remove_deposit_records: &[],
            remove_dispatch_records: &[],
            consumed_withdrawals: &[],
            new_withdraw_intents: &[],
            zone_anchor: None,
        }
    }
}

/// What [`RocksDBIO::store_update`] observed while staging, for the caller to
/// act on *after* the write committed.
#[derive(Debug, Default)]
pub struct StoreUpdateOutcome {
    /// How many deposit events were newly recorded; the rest were already
    /// pending, and so already owed.
    pub accepted_deposits: usize,
    /// Withdraw events with no matching local unseen counter, one entry per
    /// unmatched occurrence.
    pub unmatched_withdrawals: Vec<WithdrawalReconciliationKey>,
}

#[expect(
    clippy::partial_pub_fields,
    reason = "the pending-record lock is an implementation detail and must stay private"
)]
pub struct RocksDBIO {
    pub db: DBWithThreadMode<MultiThreaded>,
    /// Serializes the read-modify-write cycles over the pending cross-zone
    /// dispatch list.
    ///
    /// The list is a single value holding the whole `Vec`, and three tasks
    /// rewrite it: the watcher recording a delivery, the production loop
    /// counting a failed attempt, and the publisher's drive task settling
    /// finalized deliveries. Rocksdb makes the write atomic, not the cycle, so
    /// without this the writer that read first silently drops the others.
    pending_records: Mutex<()>,
}

impl DBIO for RocksDBIO {
    fn db(&self) -> &DBWithThreadMode<MultiThreaded> {
        &self.db
    }
}

impl RocksDBIO {
    /// Held across a pending-record read-modify-write. See
    /// [`RocksDBIO::pending_records`].
    ///
    /// A poisoned lock is recovered rather than propagated: the records behind
    /// it are a plain `Vec` that a panicking writer cannot leave half-written,
    /// since the write is a single rocksdb put.
    fn lock_pending_records(&self) -> MutexGuard<'_, ()> {
        self.pending_records
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub fn open(path: &Path) -> DbResult<Self> {
        let db_opts = Options::default();
        Self::open_inner(path, &db_opts)
    }

    pub fn create(path: &Path, genesis_block: &Block, genesis_state: &V03State) -> DbResult<Self> {
        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        let dbio = Self::open_inner(path, &db_opts)?;

        let is_start_set = dbio.get_meta_is_first_block_set()?;
        if !is_start_set {
            let block_id = genesis_block.header.block_id;
            // TODO: Shouldn't this be atomic (batched)?
            dbio.put_meta_first_block_in_db(genesis_block)?;
            dbio.put_meta_is_first_block_set()?;
            dbio.put_meta_last_block_in_db(block_id)?;
            dbio.put_meta_last_finalized_block_id(None)?;
            dbio.put_meta_latest_block_meta(&BlockMeta {
                id: genesis_block.header.block_id,
                hash: genesis_block.header.hash,
            })?;
            dbio.put_lee_state_in_db(genesis_state)?;
        }

        Ok(dbio)
    }

    /// Dump every key/value pair across all column families into a [`DbDump`]. Column families are
    /// discovered from disk, so new ones are captured without a hardcoded list.
    pub fn dump_all(&self) -> DbResult<DbDump> {
        let cf_names =
            DBWithThreadMode::<MultiThreaded>::list_cf(&Options::default(), self.db.path())
                .map_err(|rerr| {
                    DbError::rocksdb_cast_message(
                        rerr,
                        Some("Failed to list column families for dump".to_owned()),
                    )
                })?;

        let mut entries = Vec::new();
        for cf_name in cf_names {
            let cf = self.db.cf_handle(&cf_name).ok_or_else(|| {
                DbError::db_interaction_error(format!(
                    "Column family {cf_name:?} listed on disk but not opened; add it to `open_inner`"
                ))
            })?;
            for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
                let (key, value) = item.map_err(|rerr| {
                    DbError::rocksdb_cast_message(
                        rerr,
                        Some(format!(
                            "Failed to iterate column family {cf_name:?} for dump"
                        )),
                    )
                })?;
                entries.push(DbDumpEntry {
                    cf_name: cf_name.clone(),
                    key: key.into_vec(),
                    value: value.into_vec(),
                });
            }
        }
        Ok(DbDump { entries })
    }

    /// Create a fresh rocksdb at `path` populated from a [`DbDump`].
    pub fn restore_from_dump(path: &Path, dump: &DbDump) -> DbResult<Self> {
        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        let dbio = Self::open_inner(path, &db_opts)?;

        let mut batch = WriteBatch::default();
        for entry in &dump.entries {
            let cf = dbio.db.cf_handle(&entry.cf_name).ok_or_else(|| {
                DbError::db_interaction_error(format!(
                    "Unknown column family {:?} in dump",
                    entry.cf_name
                ))
            })?;
            batch.put_cf(&cf, &entry.key, &entry.value);
        }
        dbio.db.write(batch).map_err(|rerr| {
            DbError::rocksdb_cast_message(
                rerr,
                Some("Failed to write dump restore batch".to_owned()),
            )
        })?;

        Ok(dbio)
    }

    fn open_inner(path: &Path, db_opts: &Options) -> DbResult<Self> {
        let mut cf_opts = Options::default();
        cf_opts.set_max_write_buffer_number(16);

        // ToDo: Add more column families for different data
        let cfb = ColumnFamilyDescriptor::new(CF_BLOCK_NAME, cf_opts.clone());
        let cfmeta = ColumnFamilyDescriptor::new(CF_META_NAME, cf_opts.clone());
        let cfstate = ColumnFamilyDescriptor::new(CF_LEE_STATE_NAME, cf_opts.clone());

        let db = DBWithThreadMode::<MultiThreaded>::open_cf_descriptors(
            db_opts,
            path,
            vec![cfb, cfmeta, cfstate],
        )
        .map_err(|err| DbError::RocksDbError {
            error: err,
            additional_info: Some("Failed to open or create DB".to_owned()),
        })?;

        let dbio = Self {
            db,
            pending_records: Mutex::new(()),
        };
        Ok(dbio)
    }

    pub fn destroy(path: &Path) -> DbResult<()> {
        let mut cf_opts = Options::default();
        cf_opts.set_max_write_buffer_number(16);
        // ToDo: Add more column families for different data
        let _cfb = ColumnFamilyDescriptor::new(CF_BLOCK_NAME, cf_opts.clone());
        let _cfmeta = ColumnFamilyDescriptor::new(CF_META_NAME, cf_opts.clone());
        let _cfstate = ColumnFamilyDescriptor::new(CF_LEE_STATE_NAME, cf_opts.clone());

        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        DBWithThreadMode::<MultiThreaded>::destroy(&db_opts, path)
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))
    }

    // Columns

    pub fn meta_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(CF_META_NAME)
            .expect("Meta column should exist")
    }

    pub fn block_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(CF_BLOCK_NAME)
            .expect("Block column should exist")
    }

    pub fn lee_state_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(CF_LEE_STATE_NAME)
            .expect("State should exist")
    }

    // Meta

    pub fn get_meta_first_block_in_db(&self) -> DbResult<u64> {
        self.get::<FirstBlockCell>(()).map(|cell| cell.0)
    }

    pub fn get_meta_last_block_in_db(&self) -> DbResult<u64> {
        self.get::<LastBlockCell>(()).map(|cell| cell.0)
    }

    pub fn get_meta_is_first_block_set(&self) -> DbResult<bool> {
        Ok(self.get_opt::<FirstBlockSetCell>(())?.is_some())
    }

    pub fn put_lee_state_in_db(&self, state: &V03State) -> DbResult<()> {
        self.put(&LEEStateCellRef(state), ())
    }

    pub fn put_lee_state_in_db_batch(
        &self,
        state: &V03State,
        batch: &mut WriteBatch,
    ) -> DbResult<()> {
        self.put_batch(&LEEStateCellRef(state), (), batch)
    }

    pub fn put_meta_first_block_in_db(&self, block: &Block) -> DbResult<()> {
        let cf_meta = self.meta_column();
        self.db
            .put_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_FIRST_BLOCK_IN_DB_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_FIRST_BLOCK_IN_DB_KEY".to_owned()),
                    )
                })?,
                borsh::to_vec(&block.header.block_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize first block id".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        let mut batch = WriteBatch::default();
        self.put_block(block, true, &mut batch)?;
        self.db.write(batch).map_err(|rerr| {
            DbError::rocksdb_cast_message(
                rerr,
                Some("Failed to write first block in db".to_owned()),
            )
        })?;

        Ok(())
    }

    pub fn put_meta_last_block_in_db(&self, block_id: u64) -> DbResult<()> {
        self.put(&LastBlockCell(block_id), ())
    }

    fn put_meta_last_block_in_db_batch(
        &self,
        block_id: u64,
        batch: &mut WriteBatch,
    ) -> DbResult<()> {
        self.put_batch(&LastBlockCell(block_id), (), batch)
    }

    pub fn put_meta_last_finalized_block_id(&self, block_id: Option<u64>) -> DbResult<()> {
        self.put(&LastFinalizedBlockIdCell(block_id), ())
    }

    pub fn put_meta_is_first_block_set(&self) -> DbResult<()> {
        self.put(&FirstBlockSetCell(true), ())
    }

    fn put_meta_latest_block_meta(&self, block_meta: &BlockMeta) -> DbResult<()> {
        self.put(&LatestBlockMetaCellRef(block_meta), ())
    }

    fn put_meta_latest_block_meta_batch(
        &self,
        block_meta: &BlockMeta,
        batch: &mut WriteBatch,
    ) -> DbResult<()> {
        self.put_batch(&LatestBlockMetaCellRef(block_meta), (), batch)
    }

    pub fn latest_block_meta(&self) -> DbResult<Option<BlockMeta>> {
        self.get_opt::<LatestBlockMetaCellOwned>(())
            .map(|val| val.map(|cell| cell.0))
    }

    pub fn get_zone_sdk_checkpoint_bytes(&self) -> DbResult<Option<Vec<u8>>> {
        Ok(self
            .get_opt::<ZoneSdkCheckpointCellOwned>(())?
            .map(|cell| cell.0))
    }

    pub fn put_zone_sdk_checkpoint_bytes(&self, bytes: &[u8]) -> DbResult<()> {
        self.put(&ZoneSdkCheckpointCellRef(bytes), ())
    }

    /// Remove the persisted zone-sdk checkpoint so the next startup is treated as a fresh start.
    pub fn delete_zone_sdk_checkpoint_bytes(&self) -> DbResult<()> {
        self.del::<ZoneSdkCheckpointCellOwned>(())
    }

    /// The highest block id this sequencer has ever inscribed, or `None` if it
    /// has never published. Read fresh: a head rewind prunes blocks, so the
    /// stored tip is not a safe substitute.
    pub fn published_high_water(&self) -> DbResult<Option<u64>> {
        self.get_opt::<PublishedHighWaterCell>(())
            .map(|val| val.map(|cell| cell.0))
    }

    /// Raises the published high water mark to `block_id`, never lowering it.
    pub fn raise_published_high_water(&self, block_id: u64) -> DbResult<()> {
        if self
            .published_high_water()?
            .is_some_and(|mark| mark >= block_id)
        {
            return Ok(());
        }
        self.put(&PublishedHighWaterCell(block_id), ())
    }

    pub fn get_zone_anchor(&self) -> DbResult<Option<ZoneAnchorRecord>> {
        Ok(self.get_opt::<ZoneAnchorCell>(())?.map(|cell| cell.0))
    }

    pub fn put_zone_anchor(&self, anchor: &ZoneAnchorRecord) -> DbResult<()> {
        self.put(&ZoneAnchorCell(*anchor), ())
    }

    pub fn get_pending_deposit_events(&self) -> DbResult<Vec<PendingDepositEventRecord>> {
        Ok(self
            .get_opt::<PendingDepositEventsCellOwned>(())?
            .map_or_else(Vec::new, |cell| cell.0))
    }

    fn put_pending_deposit_events_batch(
        &self,
        records: &[PendingDepositEventRecord],
        batch: &mut WriteBatch,
    ) -> DbResult<()> {
        self.put_batch(&PendingDepositEventsCellRef(records), (), batch)
    }

    /// Records a single deposit event, returning whether it was new.
    /// One-shot form of [`RocksDBIO::store_update`]'s `new_deposit_events`.
    pub fn add_pending_deposit_event(&self, event: PendingDepositEventRecord) -> DbResult<bool> {
        let mut batch = WriteBatch::default();
        let accepted = self.stage_pending_deposit_events(&[event], &[], &mut batch)?;
        // A re-delivery of an already-pending deposit — the steady state — stages
        // nothing; skip the write rather than sync an empty batch.
        if batch.is_empty() {
            return Ok(false);
        }
        self.db.write(batch).map_err(|rerr| {
            DbError::rocksdb_cast_message(
                rerr,
                Some("Failed to add pending deposit event".to_owned()),
            )
        })?;
        Ok(accepted > 0)
    }

    /// Stages every mutation of the pending-deposit records into `batch`,
    /// returning how many were newly appended.
    ///
    /// The records live in a *single* whole-vector cell, so each mutation kind
    /// cannot re-read it from disk and stage its own `put`: a later read would
    /// not see the earlier staged write and would silently drop it. Everything
    /// is folded in memory here instead, and written exactly once.
    fn stage_pending_deposit_events(
        &self,
        new_events: &[PendingDepositEventRecord],
        remove_op_ids: &[HashType],
        batch: &mut WriteBatch,
    ) -> DbResult<usize> {
        if new_events.is_empty() && remove_op_ids.is_empty() {
            return Ok(0);
        }

        // A set for the membership test: a backfill can finalize many deposits
        // against many still-pending records at once, and a linear `contains`
        // per record would be quadratic.
        let to_remove: std::collections::HashSet<&HashType> = remove_op_ids.iter().collect();

        let mut records = self.get_pending_deposit_events()?;
        let before_append = records.len();

        // `accepted` is the count of records that will actually be drained on a
        // future turn, so an op id both observed and finalized in this same
        // event (backfill can deliver both at once) is neither appended nor
        // counted — its mint already happened, and counting it would log an
        // incoming mint that never comes. It is a length delta of the appends
        // alone; the retain below only touches pre-existing records.
        for event in new_events {
            if to_remove.contains(&event.deposit_op_id)
                || records
                    .iter()
                    .any(|record| record.deposit_op_id == event.deposit_op_id)
            {
                continue;
            }
            records.push(event.clone());
        }
        let accepted = records.len().saturating_sub(before_append);

        let removed = if remove_op_ids.is_empty() {
            0
        } else {
            let before_retain = records.len();
            records.retain(|record| !to_remove.contains(&record.deposit_op_id));
            before_retain.saturating_sub(records.len())
        };

        // Guard on both counts: the common finalizing event appends nothing yet
        // still mutates the cell, and a pure re-delivery mutates neither and
        // must not rewrite it.
        if accepted > 0 || removed > 0 {
            self.put_pending_deposit_events_batch(&records, batch)?;
        }
        Ok(accepted)
    }

    /// One cross-zone watcher's delivery floor on `peer_zone`'s channel, or
    /// `None` before it has delivered anything from that peer.
    pub fn get_cross_zone_peer_floor_bytes(
        &self,
        peer_zone: PeerZoneKey,
    ) -> DbResult<Option<Vec<u8>>> {
        Ok(self
            .get_opt::<PeerFloorCellOwned>(peer_zone)?
            .map(|cell| cell.0))
    }

    pub fn put_cross_zone_peer_floor_bytes(
        &self,
        peer_zone: PeerZoneKey,
        bytes: &[u8],
    ) -> DbResult<()> {
        self.put(&PeerFloorCellRef(bytes), peer_zone)
    }

    /// The last peer block one cross-zone watcher delivered from, or `None`
    /// before it has delivered anything from that peer.
    ///
    /// Write it only after that block's deliveries are recorded: a crash in
    /// between leaves a tip past deliveries that were never made, and nothing
    /// re-reads them.
    pub fn get_cross_zone_peer_tip(
        &self,
        peer_zone: PeerZoneKey,
    ) -> DbResult<Option<PeerChainTip>> {
        Ok(self.get_opt::<PeerTipCell>(peer_zone)?.map(|cell| cell.0))
    }

    pub fn put_cross_zone_peer_tip(
        &self,
        peer_zone: PeerZoneKey,
        tip: PeerChainTip,
    ) -> DbResult<()> {
        self.put(&PeerTipCell(tip), peer_zone)
    }

    /// Forgets one peer's delivery floor, so its watcher reads that channel from
    /// the peer's genesis again. Only sound while that peer has no stored tip:
    /// with one, the re-read starts below a tip nothing it reads can link to.
    ///
    /// A floor above a tip is unusable either way, since the first block read is
    /// too far ahead to link, so clearing the floor is what makes rebuilding a
    /// tip survive a crash halfway through.
    pub fn delete_cross_zone_peer_floor(&self, peer_zone: PeerZoneKey) -> DbResult<()> {
        self.del::<PeerFloorCellOwned>(peer_zone)
    }

    pub fn get_pending_cross_zone_dispatches(
        &self,
    ) -> DbResult<Vec<PendingCrossZoneDispatchRecord>> {
        Ok(self
            .get_opt::<PendingCrossZoneDispatchesCellOwned>(())?
            .map_or_else(Vec::new, |cell| cell.0))
    }

    fn put_pending_cross_zone_dispatches(
        &self,
        records: &[PendingCrossZoneDispatchRecord],
    ) -> DbResult<()> {
        self.put(&PendingCrossZoneDispatchesCellRef(records), ())
    }

    fn put_pending_cross_zone_dispatches_batch(
        &self,
        records: &[PendingCrossZoneDispatchRecord],
        batch: &mut WriteBatch,
    ) -> DbResult<()> {
        self.put_batch(&PendingCrossZoneDispatchesCellRef(records), (), batch)
    }

    /// Records every delivery one peer block carries, in a single write.
    ///
    /// Returns how many were new. Ones already recorded are skipped, so a slot
    /// the watcher re-reads is not double-tracked.
    ///
    /// Batched rather than one call per delivery because the whole list is one
    /// value: recording a block's messages one at a time rewrites the list once
    /// per message, which is quadratic in a block that carries many.
    ///
    /// Fails without writing anything if the list would exceed
    /// [`MAX_PENDING_CROSS_ZONE_DISPATCHES`]. The caller's floor then stays put
    /// and the slot is read again later, which is the difference between
    /// backpressure and an unbounded list a peer controls the size of.
    pub fn add_pending_cross_zone_dispatches(
        &self,
        dispatches: Vec<PendingCrossZoneDispatchRecord>,
    ) -> DbResult<usize> {
        if dispatches.is_empty() {
            return Ok(0);
        }

        let _pending = self.lock_pending_records();
        let mut records = self.get_pending_cross_zone_dispatches()?;
        let before = records.len();

        for dispatch in dispatches {
            if records
                .iter()
                .any(|record| record.message_key == dispatch.message_key)
            {
                continue;
            }
            records.push(dispatch);
        }

        let accepted = records.len().saturating_sub(before);
        if accepted == 0 {
            return Ok(0);
        }
        if records.len() > MAX_PENDING_CROSS_ZONE_DISPATCHES {
            return Err(DbError::db_interaction_error(format!(
                "Refusing to hold more than {MAX_PENDING_CROSS_ZONE_DISPATCHES} pending cross-zone deliveries; {before} already pending"
            )));
        }

        self.put_pending_cross_zone_dispatches(&records)?;
        Ok(accepted)
    }

    /// Counts a failed production attempt against a delivery, dropping its
    /// record once it reaches `retire_at`. Returns whether it was dropped.
    ///
    /// Dropped rather than flagged: a retired record is one the drain will never
    /// turn into a block transaction again, so nothing would ever remove it, and
    /// a peer that can make deliveries fail could grow the list without bound.
    /// The delivery is given up on either way; this way the cost is a log line
    /// rather than a permanent entry.
    ///
    /// A delivery with no record is already retired as far as this is concerned:
    /// there is nothing left to count against.
    pub fn record_dispatch_failure(&self, message_key: [u8; 32], retire_at: u32) -> DbResult<bool> {
        let _pending = self.lock_pending_records();
        let mut records = self.get_pending_cross_zone_dispatches()?;
        let Some(position) = records
            .iter()
            .position(|record| record.message_key == message_key)
        else {
            return Ok(true);
        };

        let attempts = {
            let record = &mut records[position];
            record.failed_attempts = record.failed_attempts.saturating_add(1);
            record.failed_attempts
        };
        let retired = attempts >= retire_at;
        if retired {
            records.remove(position);
        }
        self.put_pending_cross_zone_dispatches(&records)?;
        Ok(retired)
    }

    /// Drops the records of deliveries that are settled for good, outside any
    /// store update.
    ///
    /// The settlement path in [`Self::store_update`] catches a delivery as its
    /// block becomes irreversible. This catches the ones that path cannot: a
    /// record re-added after its delivery had already settled, which the watcher
    /// does whenever it re-reads a slot it has already consumed. Nothing would
    /// ever put such a key in a block again, so without this it stays for ever.
    pub fn drop_settled_cross_zone_dispatches(&self, message_keys: &[[u8; 32]]) -> DbResult<usize> {
        if message_keys.is_empty() {
            return Ok(0);
        }

        let _pending = self.lock_pending_records();
        let to_remove: std::collections::HashSet<&[u8; 32]> = message_keys.iter().collect();
        let mut records = self.get_pending_cross_zone_dispatches()?;
        let before = records.len();
        records.retain(|record| !to_remove.contains(&record.message_key));
        let removed = before.saturating_sub(records.len());

        if removed > 0 {
            self.put_pending_cross_zone_dispatches(&records)?;
        }
        Ok(removed)
    }

    /// Drops the pending records of deliveries that just became irreversible,
    /// staged into `batch` so they go with the update that made them so.
    ///
    /// Removal only, unlike [`Self::stage_pending_deposit_events`]: a delivery is
    /// recorded by the watcher through
    /// [`Self::add_pending_cross_zone_dispatch`], on its own task and outside
    /// any store update, so nothing ever adds one here.
    fn stage_removed_dispatches(
        &self,
        remove_keys: &[[u8; 32]],
        batch: &mut WriteBatch,
    ) -> DbResult<usize> {
        if remove_keys.is_empty() {
            return Ok(0);
        }

        let to_remove: std::collections::HashSet<&[u8; 32]> = remove_keys.iter().collect();
        let mut records = self.get_pending_cross_zone_dispatches()?;
        let before = records.len();
        records.retain(|record| !to_remove.contains(&record.message_key));
        let removed = before.saturating_sub(records.len());

        if removed > 0 {
            self.put_pending_cross_zone_dispatches_batch(&records, batch)?;
        }
        Ok(removed)
    }

    /// Stages the unseen-withdraw decrements for one update into `batch`,
    /// returning one entry per occurrence that matched no local counter.
    ///
    /// Occurrences are folded per key for the same reason as the deposit
    /// records: should two withdrawals in one update share a reconciliation
    /// key, a per-occurrence disk read would miss the staged decrement.
    fn stage_consumed_withdrawals(
        &self,
        withdrawals: &[WithdrawalReconciliationKey],
        batch: &mut WriteBatch,
    ) -> DbResult<Vec<WithdrawalReconciliationKey>> {
        let mut unmatched = Vec::new();
        if withdrawals.is_empty() {
            return Ok(unmatched);
        }

        // A `Vec` rather than a map: the per-update count is tiny, and it keeps
        // the staging order deterministic.
        let mut occurrences: Vec<(WithdrawalReconciliationKey, u64)> = Vec::new();
        for withdrawal in withdrawals {
            match occurrences.iter_mut().find(|(key, _)| key == withdrawal) {
                Some((_, times)) => *times = times.saturating_add(1),
                None => occurrences.push((*withdrawal, 1)),
            }
        }

        for (withdrawal, times) in occurrences {
            let stored = self
                .get_opt::<UnseenWithdrawCountCell>(withdrawal)?
                .map(|cell| cell.0);

            // A stored `count` satisfies `count + 1` occurrences: the last one
            // consumes the key by deleting it. Matches the one-shot
            // [`Self::consume_unseen_withdraw_count`].
            let matched = times.min(stored.map_or(0, |count| count.saturating_add(1)));
            unmatched.extend(std::iter::repeat_n(
                withdrawal,
                usize::try_from(times.saturating_sub(matched))
                    .expect("unmatched withdrawal count fits usize"),
            ));

            match stored.and_then(|count| count.checked_sub(times)) {
                Some(count) => {
                    self.put_batch(&UnseenWithdrawCountCell(count), withdrawal, batch)?;
                }
                // Only stage a delete for a key that was actually there, so a
                // fully unmatched update leaves the batch empty.
                None if stored.is_some() => {
                    self.del_batch::<UnseenWithdrawCountCell>(withdrawal, batch)?;
                }
                None => {}
            }
        }

        Ok(unmatched)
    }

    /// Collects the [`BedrockStatus::Finalized`] flip for every stored pending
    /// block at or below `last_finalized` into `to_write`.
    ///
    /// Reads from disk, so blocks the caller is writing itself are already in
    /// `to_write` and keep their own version — one `put` per block id, no
    /// reliance on the order writes are staged in.
    fn collect_finalized_up_to(&self, last_finalized: u64, to_write: &mut BTreeMap<u64, Block>) {
        let newly_finalized: Vec<Block> = self
            .get_all_blocks()
            .filter_map(Result::ok)
            .filter(|block| {
                matches!(block.bedrock_status, BedrockStatus::Pending)
                    && block.header.block_id <= last_finalized
            })
            .collect();

        for mut block in newly_finalized {
            block.bedrock_status = BedrockStatus::Finalized;
            to_write.entry(block.header.block_id).or_insert(block);
        }
    }

    /// Stages the unseen-withdraw increments for one update into `batch`.
    ///
    /// Occurrences are folded per key for the same reason as
    /// [`Self::stage_consumed_withdrawals`]: should two intents in one update
    /// share a reconciliation key, a per-occurrence disk read would miss the
    /// staged increment and count the pair once.
    fn stage_new_withdraw_intents(
        &self,
        withdrawals: &[WithdrawalReconciliationKey],
        batch: &mut WriteBatch,
    ) -> DbResult<()> {
        if withdrawals.is_empty() {
            return Ok(());
        }

        let mut occurrences: Vec<(WithdrawalReconciliationKey, u64)> = Vec::new();
        for withdrawal in withdrawals {
            match occurrences.iter_mut().find(|(key, _)| key == withdrawal) {
                Some((_, times)) => *times = times.saturating_add(1),
                None => occurrences.push((*withdrawal, 1)),
            }
        }

        for (withdrawal, times) in occurrences {
            let current = self
                .get_opt::<UnseenWithdrawCountCell>(withdrawal)?
                .map_or(0, |cell| cell.0);

            let next = current.checked_add(times).ok_or_else(|| {
                DbError::db_interaction_error("Unseen withdraw counter overflow".to_owned())
            })?;

            self.put_batch(&UnseenWithdrawCountCell(next), withdrawal, batch)?;
        }

        Ok(())
    }

    /// Reconciles a single L1 withdraw event, returning whether it matched a
    /// local intent. One-shot form of [`RocksDBIO::store_update`]'s
    /// `consumed_withdrawals`.
    pub fn consume_unseen_withdraw_count(
        &self,
        withdrawal: WithdrawalReconciliationKey,
    ) -> DbResult<bool> {
        let mut batch = WriteBatch::default();
        let unmatched = self.stage_consumed_withdrawals(&[withdrawal], &mut batch)?;
        self.db.write(batch).map_err(|rerr| {
            DbError::rocksdb_cast_message(
                rerr,
                Some("Failed to consume unseen withdraw count".to_owned()),
            )
        })?;
        Ok(unmatched.is_empty())
    }

    pub fn put_block(&self, block: &Block, first: bool, batch: &mut WriteBatch) -> DbResult<()> {
        if !first {
            // A produced block is the new head tip by construction: pin the
            // tip meta and drop any stale higher blocks a preceding reorg left
            // behind (mirrors `store_followed_blocks`).
            let last_curr_block = self.get_meta_last_block_in_db()?;
            for stale_id in block.header.block_id.saturating_add(1)..=last_curr_block {
                self.delete_block_payload(stale_id, batch)?;
            }
            self.put_meta_last_block_in_db_batch(block.header.block_id, batch)?;
            self.put_meta_latest_block_meta_batch(&BlockMeta::from(block), batch)?;
        }

        self.put_block_payload(block, batch)
    }

    /// Stages deletion of a block payload into `batch`.
    fn delete_block_payload(&self, block_id: u64, batch: &mut WriteBatch) -> DbResult<()> {
        let cf_block = self.block_column();
        batch.delete_cf(
            &cf_block,
            borsh::to_vec(&block_id).map_err(|err| {
                DbError::borsh_cast_message(err, Some("Failed to serialize block id".to_owned()))
            })?,
        );
        Ok(())
    }

    /// Stages just the block payload into `batch`, without touching the tip meta.
    fn put_block_payload(&self, block: &Block, batch: &mut WriteBatch) -> DbResult<()> {
        let cf_block = self.block_column();
        batch.put_cf(
            &cf_block,
            borsh::to_vec(&block.header.block_id).map_err(|err| {
                DbError::borsh_cast_message(err, Some("Failed to serialize block id".to_owned()))
            })?,
            borsh::to_vec(block).map_err(|err| {
                DbError::borsh_cast_message(err, Some("Failed to serialize block data".to_owned()))
            })?,
        );
        Ok(())
    }

    pub fn get_block(&self, block_id: u64) -> DbResult<Option<Block>> {
        self.get_opt::<BlockCell>(block_id)
            .map(|opt| opt.map(|val| val.0))
    }

    /// `(state, meta)` at the last L1-finalized block; `None` until the first
    /// finalization is observed.
    pub fn get_final_snapshot(&self) -> DbResult<Option<(V03State, BlockMeta)>> {
        let Some(meta) = self.get_opt::<FinalBlockMetaCellOwned>(())? else {
            return Ok(None);
        };
        let state = self.get::<FinalLeeStateCellOwned>(())?;
        Ok(Some((state.0, meta.0)))
    }

    fn put_final_snapshot_batch(
        &self,
        state: &V03State,
        meta: &BlockMeta,
        batch: &mut WriteBatch,
    ) -> DbResult<()> {
        self.put_batch(&FinalLeeStateCellRef(state), (), batch)?;
        self.put_batch(&FinalBlockMetaCellRef(meta), (), batch)
    }

    pub fn get_lee_state(&self) -> DbResult<V03State> {
        self.get::<LEEStateCellOwned>(()).map(|val| val.0)
    }

    pub fn delete_block(&self, block_id: u64) -> DbResult<()> {
        let cf_block = self.block_column();
        let key = borsh::to_vec(&block_id).map_err(|err| {
            DbError::borsh_cast_message(err, Some("Failed to serialize block id".to_owned()))
        })?;

        if self
            .db
            .get_cf(&cf_block, &key)
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?
            .is_none()
        {
            return Err(DbError::db_interaction_error(format!(
                "Block with id {block_id} not found"
            )));
        }

        self.db
            .delete_cf(&cf_block, key)
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        Ok(())
    }

    /// Mark every pending block with `block_id <= last_finalized` as finalized,
    /// in one atomic write. Idempotent — already-finalized blocks are skipped.
    /// One-shot form of [`RocksDBIO::store_update`]'s `finalized_up_to`.
    pub fn clean_pending_blocks_up_to(&self, last_finalized: u64) -> DbResult<()> {
        let mut to_write = BTreeMap::new();
        self.collect_finalized_up_to(last_finalized, &mut to_write);

        let mut batch = WriteBatch::default();
        for block in to_write.values() {
            self.put_block_payload(block, &mut batch)?;
        }
        self.db.write(batch).map_err(|rerr| {
            DbError::rocksdb_cast_message(
                rerr,
                Some("Failed to mark pending blocks finalized".to_owned()),
            )
        })
    }

    pub fn mark_block_as_finalized(&self, block_id: u64) -> DbResult<()> {
        self.set_block_bedrock_status(block_id, BedrockStatus::Finalized)
    }

    /// Reset every stored block to [`BedrockStatus::Pending`], for snapshotting a store to replay
    /// against a fresh Bedrock instance that knows none of the blocks yet.
    pub fn reset_all_blocks_to_pending(&self) -> DbResult<()> {
        let block_ids: Vec<u64> = self
            .get_all_blocks()
            .filter_map(Result::ok)
            .filter(|block| !matches!(block.bedrock_status, BedrockStatus::Pending))
            .map(|block| block.header.block_id)
            .collect();
        for id in block_ids {
            self.set_block_bedrock_status(id, BedrockStatus::Pending)?;
        }
        Ok(())
    }

    fn set_block_bedrock_status(&self, block_id: u64, status: BedrockStatus) -> DbResult<()> {
        let mut block = self.get_block(block_id)?.ok_or_else(|| {
            DbError::db_interaction_error(format!("Block with id {block_id} not found"))
        })?;
        block.bedrock_status = status;

        let cf_block = self.block_column();
        self.db
            .put_cf(
                &cf_block,
                borsh::to_vec(&block_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block id".to_owned()),
                    )
                })?,
                borsh::to_vec(&block).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block data".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| {
                DbError::rocksdb_cast_message(
                    rerr,
                    Some(format!("Failed to set block {block_id} bedrock status")),
                )
            })?;

        Ok(())
    }

    /// One-block form of [`Self::store_update`], with the block as the head tip
    /// and no final snapshot. Production always uses the batch form.
    #[cfg(test)]
    fn store_followed_block(
        &self,
        block: &Block,
        state: &V03State,
        finalized: bool,
    ) -> DbResult<()> {
        self.store_update(&StoreUpdate {
            blocks: &[(block, finalized)],
            head_tip: Some(&BlockMeta::from(block)),
            ..StoreUpdate::new(state)
        })
        .map(|_outcome| ())
    }

    /// Persists everything one sequencer event produced — checkpoint, blocks,
    /// tip meta, head state, final snapshot, deposit and withdraw bookkeeping
    /// and the channel anchor — in one atomic write.
    ///
    /// The tip meta is pinned to `head_tip`, and blocks stored above it (left
    /// behind by a net-shortening reorg) are deleted in the same write, so
    /// restart replay never walks past the tip.
    ///
    /// Per block: skips the payload write when the store already holds it (by
    /// id and hash), unless `finalized` is set, which rewrites it with the
    /// finalized status.
    ///
    /// The head state and tip meta are only rewritten when the chain actually
    /// moved. A checkpoint alone (the common case — every follow event carries
    /// one, most carry nothing else) must not drag a full state serialization
    /// with it.
    pub fn store_update(&self, update: &StoreUpdate<'_>) -> DbResult<StoreUpdateOutcome> {
        let _pending = self.lock_pending_records();
        let StoreUpdate {
            checkpoint,
            blocks,
            head_tip,
            head_state,
            final_snapshot,
            finalized_up_to,
            new_deposit_events,
            remove_deposit_records,
            remove_dispatch_records,
            consumed_withdrawals,
            new_withdraw_intents,
            zone_anchor,
        } = *update;

        let last_block_in_db = self.get_meta_last_block_in_db()?;
        let mut batch = WriteBatch::default();

        if let Some(bytes) = checkpoint {
            self.put_batch(&ZoneSdkCheckpointCellRef(bytes), (), &mut batch)?;
        }
        if let Some(anchor) = zone_anchor {
            self.put_batch(&ZoneAnchorCell(*anchor), (), &mut batch)?;
        }

        // Every block payload this update writes, keyed by id so a block that
        // is both explicitly written and swept by `finalized_up_to` is written
        // once, with the caller's version.
        let mut to_write: BTreeMap<u64, Block> = BTreeMap::new();

        // Whether the stored chain moved, and with it the head state. A
        // shrink-only update (orphans without adopted replacements) writes no
        // payloads but still rewinds the tip, or the stored state tears
        // against the stale disk head on the next produce.
        let mut chain_changed =
            final_snapshot.is_some() || head_tip.is_some_and(|tip| tip.id != last_block_in_db);

        for (block, finalized) in blocks {
            let already_stored = self
                .get_block(block.header.block_id)?
                .filter(|stored| stored.header.hash == block.header.hash);

            let mut block_to_write = match already_stored {
                Some(_) if !finalized => continue,
                Some(stored) => stored,
                None => (*block).clone(),
            };
            if *finalized {
                block_to_write.bedrock_status = BedrockStatus::Finalized;
            }
            to_write.insert(block_to_write.header.block_id, block_to_write);
            chain_changed = true;
        }

        if let Some(last_finalized) = finalized_up_to {
            self.collect_finalized_up_to(last_finalized, &mut to_write);
        }
        for block in to_write.values() {
            self.put_block_payload(block, &mut batch)?;
        }

        let accepted_deposits = self.stage_pending_deposit_events(
            new_deposit_events,
            remove_deposit_records,
            &mut batch,
        )?;
        self.stage_removed_dispatches(remove_dispatch_records, &mut batch)?;
        let unmatched_withdrawals =
            self.stage_consumed_withdrawals(consumed_withdrawals, &mut batch)?;
        self.stage_new_withdraw_intents(new_withdraw_intents, &mut batch)?;

        // `head_tip` is `None` only for a chain holding no blocks at all, which
        // the store — created with genesis — cannot represent. Nothing to pin.
        if chain_changed && let Some(tip) = head_tip {
            // `last_block_in_db` predates this batch, so on its own it misses
            // payloads staged above the pinned tip — a finalized block landing
            // below an adopted one rewinds the tip under blocks this same update
            // wrote. Leaving one there fails the restart replay. The deletes are
            // staged after the puts, so the batch order resolves the overlap.
            let highest_staged = to_write.last_key_value().map_or(0, |(id, _)| *id);
            for stale_id in tip.id.saturating_add(1)..=last_block_in_db.max(highest_staged) {
                self.delete_block_payload(stale_id, &mut batch)?;
            }
            self.put_meta_last_block_in_db_batch(tip.id, &mut batch)?;
            self.put_meta_latest_block_meta_batch(tip, &mut batch)?;
            self.put_lee_state_in_db_batch(head_state, &mut batch)?;
            if let Some((final_state, final_meta)) = final_snapshot {
                self.put_final_snapshot_batch(final_state, final_meta, &mut batch)?;
            }
        }

        let outcome = StoreUpdateOutcome {
            accepted_deposits,
            unmatched_withdrawals,
        };

        if batch.is_empty() {
            return Ok(outcome);
        }

        self.db.write(batch).map_err(|rerr| {
            DbError::rocksdb_cast_message(rerr, Some("Failed to write store update".to_owned()))
        })?;
        Ok(outcome)
    }

    pub fn get_all_blocks(&self) -> impl Iterator<Item = DbResult<Block>> {
        let cf_block = self.block_column();
        self.db
            .iterator_cf(&cf_block, rocksdb::IteratorMode::Start)
            .map(|res| {
                let (_key, value) = res.map_err(|rerr| {
                    DbError::rocksdb_cast_message(
                        rerr,
                        Some("Failed to get key value pair".to_owned()),
                    )
                })?;

                borsh::from_slice::<Block>(&value).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to deserialize block data".to_owned()),
                    )
                })
            })
    }

    /// Persists a block we produced, its withdraw intents, the resulting state
    /// and the publish `checkpoint` in one atomic write.
    ///
    /// The produce path is [`Self::store_update`] with a single block that is
    /// the new tip; the checkpoint belongs in the same write for the same
    /// reason it does there — it carries the sdk's `pending_txs`, so a
    /// checkpoint persisted without this block would restore a pending set
    /// that no longer contains the inscription we just published, and the sdk
    /// would never resubmit it.
    pub fn atomic_update(
        &self,
        block: &Block,
        withdrawals: &[WithdrawalReconciliationKey],
        state: &V03State,
        checkpoint: Option<&[u8]>,
    ) -> DbResult<()> {
        self.store_update(&StoreUpdate {
            checkpoint,
            blocks: &[(block, false)],
            head_tip: Some(&BlockMeta::from(block)),
            new_withdraw_intents: withdrawals,
            ..StoreUpdate::new(state)
        })
        .map(|_outcome| ())
    }
}

#[cfg(test)]
mod tests;
