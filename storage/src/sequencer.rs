use std::{path::Path, sync::Arc};

use common::block::{BedrockStatus, Block, BlockMeta, MantleMsgId};
use nssa::V02State;
use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, MultiThreaded, Options, WriteBatch,
};

use crate::error::DbError;

/// Maximal size of stored blocks in base.
///
/// Used to control db size.
///
/// Currently effectively unbounded.
pub const BUFF_SIZE_ROCKSDB: usize = usize::MAX;

/// Size of stored blocks cache in memory.
///
/// Keeping small to not run out of memory.
pub const CACHE_SIZE: usize = 1000;

/// Key base for storing metainformation about id of first block in db.
pub const DB_META_FIRST_BLOCK_IN_DB_KEY: &str = "first_block_in_db";
/// Key base for storing metainformation about id of last current block in db.
pub const DB_META_LAST_BLOCK_IN_DB_KEY: &str = "last_block_in_db";
/// Key base for storing metainformation which describe if first block has been set.
pub const DB_META_FIRST_BLOCK_SET_KEY: &str = "first_block_set";
/// Key base for storing metainformation about the last finalized block on Bedrock.
pub const DB_META_LAST_FINALIZED_BLOCK_ID: &str = "last_finalized_block_id";
/// Key base for storing metainformation about the latest block meta.
pub const DB_META_LATEST_BLOCK_META_KEY: &str = "latest_block_meta";

/// Key base for storing the NSSA state.
pub const DB_NSSA_STATE_KEY: &str = "nssa_state";

/// Name of block column family.
pub const CF_BLOCK_NAME: &str = "cf_block";
/// Name of meta column family.
pub const CF_META_NAME: &str = "cf_meta";
/// Name of state column family.
pub const CF_NSSA_STATE_NAME: &str = "cf_nssa_state";

pub type DbResult<T> = Result<T, DbError>;

pub struct RocksDBIO {
    pub db: DBWithThreadMode<MultiThreaded>,
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

    pub fn meta_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db.cf_handle(CF_META_NAME).unwrap()
    }

    pub fn block_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db.cf_handle(CF_BLOCK_NAME).unwrap()
    }

    pub fn nssa_state_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db.cf_handle(CF_NSSA_STATE_NAME).unwrap()
    }

    pub fn get_meta_first_block_in_db(&self) -> DbResult<u64> {
        let cf_meta = self.meta_column();
        let res = self
            .db
            .get_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_FIRST_BLOCK_IN_DB_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_FIRST_BLOCK_IN_DB_KEY".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(borsh::from_slice::<u64>(&data).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to deserialize first block".to_owned()),
                )
            })?)
        } else {
            Err(DbError::db_interaction_error(
                "First block not found".to_owned(),
            ))
        }
    }

    pub fn get_meta_last_block_in_db(&self) -> DbResult<u64> {
        let cf_meta = self.meta_column();
        let res = self
            .db
            .get_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_LAST_BLOCK_IN_DB_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_LAST_BLOCK_IN_DB_KEY".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(borsh::from_slice::<u64>(&data).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to deserialize last block".to_owned()),
                )
            })?)
        } else {
            Err(DbError::db_interaction_error(
                "Last block not found".to_owned(),
            ))
        }
    }

    pub fn get_meta_is_first_block_set(&self) -> DbResult<bool> {
        let cf_meta = self.meta_column();
        let res = self
            .db
            .get_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_FIRST_BLOCK_SET_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_FIRST_BLOCK_SET_KEY".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        Ok(res.is_some())
    }

    pub fn put_nssa_state_in_db(&self, state: &V02State, batch: &mut WriteBatch) -> DbResult<()> {
        let cf_nssa_state = self.nssa_state_column();
        batch.put_cf(
            &cf_nssa_state,
            borsh::to_vec(&DB_NSSA_STATE_KEY).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to serialize DB_NSSA_STATE_KEY".to_owned()),
                )
            })?,
            borsh::to_vec(state).map_err(|err| {
                DbError::borsh_cast_message(err, Some("Failed to serialize NSSA state".to_owned()))
            })?,
        );

        Ok(())
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
        let cf_meta = self.meta_column();
        self.db
            .put_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_LAST_BLOCK_IN_DB_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_LAST_BLOCK_IN_DB_KEY".to_owned()),
                    )
                })?,
                borsh::to_vec(&block_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize last block id".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;
        Ok(())
    }

    fn put_meta_last_block_in_db_batch(
        &self,
        block_id: u64,
        batch: &mut WriteBatch,
    ) -> DbResult<()> {
        let cf_meta = self.meta_column();
        batch.put_cf(
            &cf_meta,
            borsh::to_vec(&DB_META_LAST_BLOCK_IN_DB_KEY).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to serialize DB_META_LAST_BLOCK_IN_DB_KEY".to_owned()),
                )
            })?,
            borsh::to_vec(&block_id).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to serialize last block id".to_owned()),
                )
            })?,
        );
        Ok(())
    }

    pub fn put_meta_last_finalized_block_id(&self, block_id: Option<u64>) -> DbResult<()> {
        let cf_meta = self.meta_column();
        self.db
            .put_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_LAST_FINALIZED_BLOCK_ID).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_LAST_FINALIZED_BLOCK_ID".to_owned()),
                    )
                })?,
                borsh::to_vec(&block_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize last block id".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;
        Ok(())
    }

    pub fn put_meta_is_first_block_set(&self) -> DbResult<()> {
        let cf_meta = self.meta_column();
        self.db
            .put_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_FIRST_BLOCK_SET_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_FIRST_BLOCK_SET_KEY".to_owned()),
                    )
                })?,
                [1_u8; 1],
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;
        Ok(())
    }

    fn put_meta_latest_block_meta(&self, block_meta: &BlockMeta) -> DbResult<()> {
        let cf_meta = self.meta_column();
        self.db
            .put_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_LATEST_BLOCK_META_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_LATEST_BLOCK_META_KEY".to_owned()),
                    )
                })?,
                borsh::to_vec(&block_meta).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize latest block meta".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;
        Ok(())
    }

    fn put_meta_latest_block_meta_batch(
        &self,
        block_meta: &BlockMeta,
        batch: &mut WriteBatch,
    ) -> DbResult<()> {
        let cf_meta = self.meta_column();
        batch.put_cf(
            &cf_meta,
            borsh::to_vec(&DB_META_LATEST_BLOCK_META_KEY).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to serialize DB_META_LATEST_BLOCK_META_KEY".to_owned()),
                )
            })?,
            borsh::to_vec(&block_meta).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to serialize latest block meta".to_owned()),
                )
            })?,
        );
        Ok(())
    }

    pub fn latest_block_meta(&self) -> DbResult<BlockMeta> {
        let cf_meta = self.meta_column();
        let res = self
            .db
            .get_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_LATEST_BLOCK_META_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_LATEST_BLOCK_META_KEY".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(borsh::from_slice::<BlockMeta>(&data).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to deserialize latest block meta".to_owned()),
                )
            })?)
        } else {
            Err(DbError::db_interaction_error(
                "Latest block meta not found".to_owned(),
            ))
        }
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
        let cf_block = self.block_column();
        let res = self
            .db
            .get_cf(
                &cf_block,
                borsh::to_vec(&block_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block id".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(Some(borsh::from_slice::<Block>(&data).map_err(|serr| {
                DbError::borsh_cast_message(
                    serr,
                    Some("Failed to deserialize block data".to_owned()),
                )
            })?))
        } else {
            Ok(None)
        }
    }

    pub fn get_nssa_state(&self) -> DbResult<V02State> {
        let cf_nssa_state = self.nssa_state_column();
        let res = self
            .db
            .get_cf(
                &cf_nssa_state,
                borsh::to_vec(&DB_NSSA_STATE_KEY).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block id".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(borsh::from_slice::<V02State>(&data).map_err(|serr| {
                DbError::borsh_cast_message(
                    serr,
                    Some("Failed to deserialize block data".to_owned()),
                )
            })?)
        } else {
            Err(DbError::db_interaction_error(
                "NSSA state not found".to_owned(),
            ))
        }
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
        state: &V02State,
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
