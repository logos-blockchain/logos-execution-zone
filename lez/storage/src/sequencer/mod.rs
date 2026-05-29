use std::{path::Path, sync::Arc};

use common::{
    HashType,
    block::{BedrockStatus, Block, BlockMeta, MantleMsgId},
};
use lee::V03State;
use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, MultiThreaded, Options, WriteBatch,
};

use crate::{
    CF_BLOCK_NAME, CF_META_NAME, DB_META_FIRST_BLOCK_IN_DB_KEY, DBIO, DbResult,
    cells::shared_cells::{BlockCell, FirstBlockCell, FirstBlockSetCell, LastBlockCell},
    error::DbError,
    sequencer::sequencer_cells::{
        LEEStateCellOwned, LEEStateCellRef, LastFinalizedBlockIdCell, LatestBlockMetaCellOwned,
        LatestBlockMetaCellRef, PendingDepositEventRecord, PendingDepositEventsCellOwned,
        PendingDepositEventsCellRef, ZoneSdkCheckpointCellOwned, ZoneSdkCheckpointCellRef,
    },
};

pub mod sequencer_cells;

/// Key base for storing metainformation about the last finalized block on Bedrock.
pub const DB_META_LAST_FINALIZED_BLOCK_ID: &str = "last_finalized_block_id";
/// Key base for storing metainformation about the latest block meta.
pub const DB_META_LATEST_BLOCK_META_KEY: &str = "latest_block_meta";
/// Key base for storing the zone-sdk sequencer checkpoint (opaque bytes).
pub const DB_META_ZONE_SDK_CHECKPOINT_KEY: &str = "zone_sdk_checkpoint";
/// Key base for storing queued deposit events that were not yet
/// fulfilled on L2.
pub const DB_META_PENDING_DEPOSIT_EVENTS_KEY: &str = "pending_deposit_events";

/// Key base for storing the LEE state.
pub const DB_LEE_STATE_KEY: &str = "lee_state";

/// Name of state column family.
pub const CF_LEE_STATE_NAME: &str = "cf_lee_state";

pub struct RocksDBIO {
    pub db: DBWithThreadMode<MultiThreaded>,
}

impl DBIO for RocksDBIO {
    fn db(&self) -> &DBWithThreadMode<MultiThreaded> {
        &self.db
    }
}

impl RocksDBIO {
    pub fn open(path: &Path) -> DbResult<Self> {
        let db_opts = Options::default();
        Self::open_inner(path, &db_opts)
    }

    pub fn create(
        path: &Path,
        genesis_block: &Block,
        genesis_msg_id: MantleMsgId,
        genesis_state: &V03State,
    ) -> DbResult<Self> {
        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        let dbio = Self::open_inner(path, &db_opts)?;

        let is_start_set = dbio.get_meta_is_first_block_set()?;
        if !is_start_set {
            let block_id = genesis_block.header.block_id;
            // TODO: Shouldn't this be atomic (batched)?
            dbio.put_meta_first_block_in_db(genesis_block, genesis_msg_id)?;
            dbio.put_meta_is_first_block_set()?;
            dbio.put_meta_last_block_in_db(block_id)?;
            dbio.put_meta_last_finalized_block_id(None)?;
            dbio.put_meta_latest_block_meta(&BlockMeta {
                id: genesis_block.header.block_id,
                hash: genesis_block.header.hash,
                msg_id: genesis_msg_id,
            })?;
            dbio.put_lee_state_in_db(genesis_state)?;
        }

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

        let dbio = Self { db };
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

    pub fn put_meta_first_block_in_db(&self, block: &Block, msg_id: MantleMsgId) -> DbResult<()> {
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
        self.put_block(block, msg_id, true, &mut batch)?;
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

    pub fn latest_block_meta(&self) -> DbResult<BlockMeta> {
        self.get::<LatestBlockMetaCellOwned>(()).map(|val| val.0)
    }

    pub fn get_zone_sdk_checkpoint_bytes(&self) -> DbResult<Option<Vec<u8>>> {
        Ok(self
            .get_opt::<ZoneSdkCheckpointCellOwned>(())?
            .map(|cell| cell.0))
    }

    pub fn put_zone_sdk_checkpoint_bytes(&self, bytes: &[u8]) -> DbResult<()> {
        self.put(&ZoneSdkCheckpointCellRef(bytes), ())
    }

    pub fn get_pending_deposit_events(&self) -> DbResult<Vec<PendingDepositEventRecord>> {
        Ok(self
            .get_opt::<PendingDepositEventsCellOwned>(())?
            .map_or_else(Vec::new, |cell| cell.0))
    }

    fn put_pending_deposit_events(&self, records: &[PendingDepositEventRecord]) -> DbResult<()> {
        self.put(&PendingDepositEventsCellRef(records), ())
    }

    pub fn add_pending_deposit_event(&self, event: PendingDepositEventRecord) -> DbResult<bool> {
        let mut records = self.get_pending_deposit_events()?;
        if records
            .iter()
            .any(|record| record.deposit_op_id == event.deposit_op_id)
        {
            return Ok(false);
        }
        records.push(event);
        self.put_pending_deposit_events(&records)?;
        Ok(true)
    }

    pub fn mark_pending_deposit_events_submitted(
        &self,
        deposit_op_ids: &[HashType],
        submitted_block_id: u64,
    ) -> DbResult<usize> {
        let mut records = self.get_pending_deposit_events()?;
        let mut updated: usize = 0;

        for record in records
            .iter_mut()
            .filter(|record| deposit_op_ids.contains(&record.deposit_op_id))
        {
            record.submitted_in_block_id = Some(submitted_block_id);
            updated = updated.saturating_add(1);
        }

        if updated > 0 {
            self.put_pending_deposit_events(&records)?;
        }

        Ok(updated)
    }

    pub fn remove_fulfilled_pending_deposit_events_up_to_block(
        &self,
        finalized_block_id: u64,
    ) -> DbResult<usize> {
        let mut records = self.get_pending_deposit_events()?;
        let before = records.len();
        records.retain(|record| {
            record
                .submitted_in_block_id
                .is_none_or(|submitted_id| submitted_id > finalized_block_id)
        });

        let removed = before.saturating_sub(records.len());
        if removed > 0 {
            self.put_pending_deposit_events(&records)?;
        }

        Ok(removed)
    }

    pub fn put_block(
        &self,
        block: &Block,
        msg_id: MantleMsgId,
        first: bool,
        batch: &mut WriteBatch,
    ) -> DbResult<()> {
        let cf_block = self.block_column();

        if !first {
            let last_curr_block = self.get_meta_last_block_in_db()?;

            if block.header.block_id > last_curr_block {
                self.put_meta_last_block_in_db_batch(block.header.block_id, batch)?;
                self.put_meta_latest_block_meta_batch(
                    &BlockMeta {
                        id: block.header.block_id,
                        hash: block.header.hash,
                        msg_id,
                    },
                    batch,
                )?;
            }
        }

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

    /// Mark every pending block with `block_id <= last_finalized` as finalized.
    /// Idempotent — already-finalized blocks are skipped.
    pub fn clean_pending_blocks_up_to(&self, last_finalized: u64) -> DbResult<()> {
        let pending_ids: Vec<u64> = self
            .get_all_blocks()
            .filter_map(Result::ok)
            .filter(|b| matches!(b.bedrock_status, BedrockStatus::Pending))
            .map(|b| b.header.block_id)
            .filter(|id| *id <= last_finalized)
            .collect();
        for id in pending_ids {
            self.mark_block_as_finalized(id)?;
        }
        Ok(())
    }

    pub fn mark_block_as_finalized(&self, block_id: u64) -> DbResult<()> {
        let mut block = self.get_block(block_id)?.ok_or_else(|| {
            DbError::db_interaction_error(format!("Block with id {block_id} not found"))
        })?;
        block.bedrock_status = BedrockStatus::Finalized;

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
                    Some(format!("Failed to mark block {block_id} as finalized")),
                )
            })?;

        Ok(())
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

    pub fn atomic_update(
        &self,
        block: &Block,
        msg_id: MantleMsgId,
        state: &V03State,
    ) -> DbResult<()> {
        let block_id = block.header.block_id;
        let mut batch = WriteBatch::default();
        self.put_block(block, msg_id, false, &mut batch)?;
        self.put_lee_state_in_db_batch(state, &mut batch)?;
        self.db.write(batch).map_err(|rerr| {
            DbError::rocksdb_cast_message(
                rerr,
                Some(format!("Failed to udpate db with block {block_id}")),
            )
        })
    }
}
