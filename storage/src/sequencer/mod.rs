use std::{path::Path, sync::Arc};

use common::block::{BedrockStatus, Block, BlockMeta, MantleMsgId};
use nssa::V03State;
use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, MultiThreaded, Options, WriteBatch,
};

use crate::{
    CF_BLOCK_NAME, CF_META_NAME, DB_META_FIRST_BLOCK_IN_DB_KEY, DBIO, DbResult,
    cells::shared_cells::{BlockCell, FirstBlockCell, FirstBlockSetCell, LastBlockCell},
    error::DbError,
    sequencer::sequencer_cells::{
        LastFinalizedBlockIdCell, LatestBlockMetaCellOwned, LatestBlockMetaCellRef,
        NSSAStateCellOwned, NSSAStateCellRef,
    },
};

pub mod sequencer_cells;

/// Key base for storing metainformation about the last finalized block on Bedrock.
pub const DB_META_LAST_FINALIZED_BLOCK_ID: &str = "last_finalized_block_id";
/// Key base for storing metainformation about the latest block meta.
pub const DB_META_LATEST_BLOCK_META_KEY: &str = "latest_block_meta";

/// Key base for storing the NSSA state.
pub const DB_NSSA_STATE_KEY: &str = "nssa_state";

/// Name of state column family.
pub const CF_NSSA_STATE_NAME: &str = "cf_nssa_state";

pub struct RocksDBIO {
    pub db: DBWithThreadMode<MultiThreaded>,
}

impl DBIO for RocksDBIO {
    fn db(&self) -> &DBWithThreadMode<MultiThreaded> {
        &self.db
    }
}

impl RocksDBIO {
    pub fn open_or_create(
        path: &Path,
        genesis_block: &Block,
        genesis_msg_id: MantleMsgId,
    ) -> DbResult<Self> {
        let mut cf_opts = Options::default();
        cf_opts.set_max_write_buffer_number(16);
        // ToDo: Add more column families for different data
        let cfb = ColumnFamilyDescriptor::new(CF_BLOCK_NAME, cf_opts.clone());
        let cfmeta = ColumnFamilyDescriptor::new(CF_META_NAME, cf_opts.clone());
        let cfstate = ColumnFamilyDescriptor::new(CF_NSSA_STATE_NAME, cf_opts.clone());

        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        let db = DBWithThreadMode::<MultiThreaded>::open_cf_descriptors(
            &db_opts,
            path,
            vec![cfb, cfmeta, cfstate],
        )
        .map_err(|err| DbError::RocksDbError {
            error: err,
            additional_info: Some("Failed to open or create DB".to_owned()),
        })?;

        let dbio = Self { db };

        let is_start_set = dbio.get_meta_is_first_block_set()?;
        if !is_start_set {
            let block_id = genesis_block.header.block_id;
            dbio.put_meta_first_block_in_db(genesis_block, genesis_msg_id)?;
            dbio.put_meta_is_first_block_set()?;
            dbio.put_meta_last_block_in_db(block_id)?;
            dbio.put_meta_last_finalized_block_id(None)?;
            dbio.put_meta_latest_block_meta(&BlockMeta {
                id: genesis_block.header.block_id,
                hash: genesis_block.header.hash,
                msg_id: genesis_msg_id,
            })?;
        }

        Ok(dbio)
    }

    pub fn destroy(path: &Path) -> DbResult<()> {
        let mut cf_opts = Options::default();
        cf_opts.set_max_write_buffer_number(16);
        // ToDo: Add more column families for different data
        let _cfb = ColumnFamilyDescriptor::new(CF_BLOCK_NAME, cf_opts.clone());
        let _cfmeta = ColumnFamilyDescriptor::new(CF_META_NAME, cf_opts.clone());
        let _cfstate = ColumnFamilyDescriptor::new(CF_NSSA_STATE_NAME, cf_opts.clone());

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

    pub fn nssa_state_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(CF_NSSA_STATE_NAME)
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

    pub fn put_nssa_state_in_db(&self, state: &V03State, batch: &mut WriteBatch) -> DbResult<()> {
        self.put_batch(&NSSAStateCellRef(state), (), batch)
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

    pub fn get_nssa_state(&self) -> DbResult<V03State> {
        self.get::<NSSAStateCellOwned>(()).map(|val| val.0)
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
        self.put_nssa_state_in_db(state, &mut batch)?;
        self.db.write(batch).map_err(|rerr| {
            DbError::rocksdb_cast_message(
                rerr,
                Some(format!("Failed to udpate db with block {block_id}")),
            )
        })
    }
}
