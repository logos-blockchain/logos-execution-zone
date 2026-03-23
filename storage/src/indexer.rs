use std::{collections::HashMap, path::Path, sync::Arc};

use common::{
    block::{Block, BlockId},
    transaction::NSSATransaction,
};
use nssa::V03State;
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
/// Key base for storing metainformation about id of last observed L1 lib header in db.
pub const DB_META_LAST_OBSERVED_L1_LIB_HEADER_ID_IN_DB_KEY: &str =
    "last_observed_l1_lib_header_in_db";
/// Key base for storing metainformation which describe if first block has been set.
pub const DB_META_FIRST_BLOCK_SET_KEY: &str = "first_block_set";
/// Key base for storing metainformation about the last breakpoint.
pub const DB_META_LAST_BREAKPOINT_ID: &str = "last_breakpoint_id";

/// Interval between state breakpoints.
pub const BREAKPOINT_INTERVAL: u8 = 100;

/// Name of block column family.
pub const CF_BLOCK_NAME: &str = "cf_block";
/// Name of meta column family.
pub const CF_META_NAME: &str = "cf_meta";
/// Name of breakpoint column family.
pub const CF_BREAKPOINT_NAME: &str = "cf_breakpoint";
/// Name of hash to id map column family.
pub const CF_HASH_TO_ID: &str = "cf_hash_to_id";
/// Name of tx hash to id map column family.
pub const CF_TX_TO_ID: &str = "cf_tx_to_id";
/// Name of account meta column family.
pub const CF_ACC_META: &str = "cf_acc_meta";
/// Name of account id to tx hash map column family.
pub const CF_ACC_TO_TX: &str = "cf_acc_to_tx";

pub type DbResult<T> = Result<T, DbError>;

pub struct RocksDBIO {
    pub db: DBWithThreadMode<MultiThreaded>,
}

impl RocksDBIO {
    pub fn open_or_create(
        path: &Path,
        genesis_block: &Block,
        initial_state: &V03State,
    ) -> DbResult<Self> {
        let mut cf_opts = Options::default();
        cf_opts.set_max_write_buffer_number(16);
        // ToDo: Add more column families for different data
        let cfb = ColumnFamilyDescriptor::new(CF_BLOCK_NAME, cf_opts.clone());
        let cfmeta = ColumnFamilyDescriptor::new(CF_META_NAME, cf_opts.clone());
        let cfbreakpoint = ColumnFamilyDescriptor::new(CF_BREAKPOINT_NAME, cf_opts.clone());
        let cfhti = ColumnFamilyDescriptor::new(CF_HASH_TO_ID, cf_opts.clone());
        let cftti = ColumnFamilyDescriptor::new(CF_TX_TO_ID, cf_opts.clone());
        let cfameta = ColumnFamilyDescriptor::new(CF_ACC_META, cf_opts.clone());
        let cfatt = ColumnFamilyDescriptor::new(CF_ACC_TO_TX, cf_opts.clone());

        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        let db = DBWithThreadMode::<MultiThreaded>::open_cf_descriptors(
            &db_opts,
            path,
            vec![cfb, cfmeta, cfbreakpoint, cfhti, cftti, cfameta, cfatt],
        )
        .map_err(|err| DbError::RocksDbError {
            error: err,
            additional_info: Some("Failed to open or create DB".to_owned()),
        })?;

        let dbio = Self { db };

        let is_start_set = dbio.get_meta_is_first_block_set()?;
        if !is_start_set {
            let block_id = genesis_block.header.block_id;
            dbio.put_meta_last_block_in_db(block_id)?;
            dbio.put_meta_first_block_in_db(genesis_block)?;
            dbio.put_meta_is_first_block_set()?;

            // First breakpoint setup
            dbio.put_breakpoint(0, initial_state)?;
            dbio.put_meta_last_breakpoint_id(0)?;
        }

        Ok(dbio)
    }

    pub fn destroy(path: &Path) -> DbResult<()> {
        let mut cf_opts = Options::default();
        cf_opts.set_max_write_buffer_number(16);
        // ToDo: Add more column families for different data
        let _cfb = ColumnFamilyDescriptor::new(CF_BLOCK_NAME, cf_opts.clone());
        let _cfmeta = ColumnFamilyDescriptor::new(CF_META_NAME, cf_opts.clone());
        let _cfsnapshot = ColumnFamilyDescriptor::new(CF_BREAKPOINT_NAME, cf_opts.clone());
        let _cfhti = ColumnFamilyDescriptor::new(CF_HASH_TO_ID, cf_opts.clone());
        let _cftti = ColumnFamilyDescriptor::new(CF_TX_TO_ID, cf_opts.clone());
        let _cfameta = ColumnFamilyDescriptor::new(CF_ACC_META, cf_opts.clone());
        let _cfatt = ColumnFamilyDescriptor::new(CF_ACC_TO_TX, cf_opts.clone());

        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        DBWithThreadMode::<MultiThreaded>::destroy(&db_opts, path)
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))
    }

    // Columns

    pub fn meta_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db.cf_handle(CF_META_NAME).unwrap()
    }

    pub fn block_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db.cf_handle(CF_BLOCK_NAME).unwrap()
    }

    pub fn breakpoint_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db.cf_handle(CF_BREAKPOINT_NAME).unwrap()
    }

    pub fn hash_to_id_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db.cf_handle(CF_HASH_TO_ID).unwrap()
    }

    pub fn tx_hash_to_id_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db.cf_handle(CF_TX_TO_ID).unwrap()
    }

    pub fn account_id_to_tx_hash_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db.cf_handle(CF_ACC_TO_TX).unwrap()
    }

    pub fn account_meta_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db.cf_handle(CF_ACC_META).unwrap()
    }

    // Meta

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

    pub fn get_meta_last_observed_l1_lib_header_in_db(&self) -> DbResult<Option<[u8; 32]>> {
        let cf_meta = self.meta_column();
        let res = self
            .db
            .get_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_LAST_OBSERVED_L1_LIB_HEADER_ID_IN_DB_KEY).map_err(
                    |err| {
                        DbError::borsh_cast_message(
                        err,
                        Some(
                            "Failed to serialize DB_META_LAST_OBSERVED_L1_LIB_HEADER_ID_IN_DB_KEY".to_owned(),
                        ),
                    )
                    },
                )?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        res.map(|data| {
            borsh::from_slice::<[u8; 32]>(&data).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to deserialize last l1 lib header".to_owned()),
                )
            })
        })
        .transpose()
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

    pub fn get_meta_last_breakpoint_id(&self) -> DbResult<u64> {
        let cf_meta = self.meta_column();
        let res = self
            .db
            .get_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_LAST_BREAKPOINT_ID).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_LAST_BREAKPOINT_ID".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(borsh::from_slice::<u64>(&data).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to deserialize last breakpoint id".to_owned()),
                )
            })?)
        } else {
            Err(DbError::db_interaction_error(
                "Last breakpoint id not found".to_owned(),
            ))
        }
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

        self.put_block(block, [0; 32])?;
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

    pub fn put_meta_last_observed_l1_lib_header_in_db(
        &self,
        l1_lib_header: [u8; 32],
    ) -> DbResult<()> {
        let cf_meta = self.meta_column();
        self.db
            .put_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_LAST_OBSERVED_L1_LIB_HEADER_ID_IN_DB_KEY).map_err(
                    |err| {
                        DbError::borsh_cast_message(
                        err,
                        Some(
                            "Failed to serialize DB_META_LAST_OBSERVED_L1_LIB_HEADER_ID_IN_DB_KEY".to_owned(),
                        ),
                    )
                    },
                )?,
                borsh::to_vec(&l1_lib_header).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize last l1 block header".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;
        Ok(())
    }

    pub fn put_meta_last_breakpoint_id(&self, br_id: u64) -> DbResult<()> {
        let cf_meta = self.meta_column();
        self.db
            .put_cf(
                &cf_meta,
                borsh::to_vec(&DB_META_LAST_BREAKPOINT_ID).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize DB_META_LAST_BREAKPOINT_ID".to_owned()),
                    )
                })?,
                borsh::to_vec(&br_id).map_err(|err| {
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

    // Block

    pub fn put_block(&self, block: &Block, l1_lib_header: [u8; 32]) -> DbResult<()> {
        let cf_block = self.block_column();
        let cf_hti = self.hash_to_id_column();
        let cf_tti: Arc<BoundColumnFamily<'_>> = self.tx_hash_to_id_column();

        // ToDo: rewrite this with write batching

        self.db
            .put_cf(
                &cf_block,
                borsh::to_vec(&block.header.block_id).map_err(|err| {
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
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        let last_curr_block = self.get_meta_last_block_in_db()?;

        if block.header.block_id > last_curr_block {
            self.put_meta_last_block_in_db(block.header.block_id)?;
            self.put_meta_last_observed_l1_lib_header_in_db(l1_lib_header)?;
        }

        self.db
            .put_cf(
                &cf_hti,
                borsh::to_vec(&block.header.hash).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block hash".to_owned()),
                    )
                })?,
                borsh::to_vec(&block.header.block_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block id".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        let mut acc_to_tx_map: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();

        for tx in &block.body.transactions {
            let tx_hash = tx.hash();

            self.db
                .put_cf(
                    &cf_tti,
                    borsh::to_vec(&tx_hash).map_err(|err| {
                        DbError::borsh_cast_message(
                            err,
                            Some("Failed to serialize tx hash".to_owned()),
                        )
                    })?,
                    borsh::to_vec(&block.header.block_id).map_err(|err| {
                        DbError::borsh_cast_message(
                            err,
                            Some("Failed to serialize block id".to_owned()),
                        )
                    })?,
                )
                .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

            let acc_ids = tx
                .affected_public_account_ids()
                .into_iter()
                .map(nssa::AccountId::into_value)
                .collect::<Vec<_>>();

            for acc_id in acc_ids {
                acc_to_tx_map
                    .entry(acc_id)
                    .and_modify(|tx_hashes| tx_hashes.push(tx_hash.into()))
                    .or_insert_with(|| vec![tx_hash.into()]);
            }
        }

        #[expect(
            clippy::iter_over_hash_type,
            reason = "RocksDB will keep ordering persistent"
        )]
        for (acc_id, tx_hashes) in acc_to_tx_map {
            self.put_account_transactions(acc_id, &tx_hashes)?;
        }

        if block
            .header
            .block_id
            .is_multiple_of(u64::from(BREAKPOINT_INTERVAL))
        {
            self.put_next_breakpoint()?;
        }

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

    pub fn get_block_batch(&self, before: Option<BlockId>, limit: u64) -> DbResult<Vec<Block>> {
        let cf_block = self.block_column();
        let mut block_batch = vec![];

        // Determine the starting block ID
        let start_block_id = if let Some(before_id) = before {
            before_id.saturating_sub(1)
        } else {
            // Get the latest block ID
            self.get_meta_last_block_in_db()?
        };

        // ToDo: Multi get this

        for i in 0..limit {
            let block_id = start_block_id.saturating_sub(i);
            if block_id == 0 {
                break;
            }

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

            let block = if let Some(data) = res {
                Ok(borsh::from_slice::<Block>(&data).map_err(|serr| {
                    DbError::borsh_cast_message(
                        serr,
                        Some("Failed to deserialize block data".to_owned()),
                    )
                })?)
            } else {
                // Block not found, assuming that previous one was the last
                break;
            }?;

            block_batch.push(block);
        }

        Ok(block_batch)
    }

    // State

    pub fn put_breakpoint(&self, br_id: u64, breakpoint: &V03State) -> DbResult<()> {
        let cf_br = self.breakpoint_column();

        self.db
            .put_cf(
                &cf_br,
                borsh::to_vec(&br_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize breakpoint id".to_owned()),
                    )
                })?,
                borsh::to_vec(&breakpoint).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize breakpoint data".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))
    }

    pub fn get_breakpoint(&self, br_id: u64) -> DbResult<V03State> {
        let cf_br = self.breakpoint_column();
        let res = self
            .db
            .get_cf(
                &cf_br,
                borsh::to_vec(&br_id).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize breakpoint id".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(borsh::from_slice::<V03State>(&data).map_err(|serr| {
                DbError::borsh_cast_message(
                    serr,
                    Some("Failed to deserialize breakpoint data".to_owned()),
                )
            })?)
        } else {
            // Note: this is not a `DbError::NotFound` case, because we expect that all searched
            // breakpoints will be present in db as this is an internal method.
            Err(DbError::db_interaction_error(
                "Breakpoint on this id not found".to_owned(),
            ))
        }
    }

    pub fn calculate_state_for_id(&self, block_id: u64) -> DbResult<V03State> {
        let last_block = self.get_meta_last_block_in_db()?;

        if block_id <= last_block {
            let br_id = closest_breakpoint_id(block_id);
            let mut breakpoint = self.get_breakpoint(br_id)?;

            // ToDo: update it to handle any genesis id
            // right now works correctly only if genesis_id < BREAKPOINT_INTERVAL
            let start = if br_id != 0 {
                u64::from(BREAKPOINT_INTERVAL)
                    .checked_mul(br_id)
                    .expect("Reached maximum breakpoint id")
            } else {
                self.get_meta_first_block_in_db()?
            };

            for id in start..=block_id {
                let block = self.get_block(id)?.ok_or_else(|| {
                    DbError::db_interaction_error(format!("Block with id {id} not found"))
                })?;

                for transaction in block.body.transactions {
                    transaction
                        .transaction_stateless_check()
                        .map_err(|err| {
                            DbError::db_interaction_error(format!(
                                "transaction pre check failed with err {err:?}"
                            ))
                        })?
                        .execute_check_on_state(&mut breakpoint)
                        .map_err(|err| {
                            DbError::db_interaction_error(format!(
                                "transaction execution failed with err {err:?}"
                            ))
                        })?;
                }
            }

            Ok(breakpoint)
        } else {
            Err(DbError::db_interaction_error(format!(
                "Block with id {block_id} not found"
            )))
        }
    }

    pub fn final_state(&self) -> DbResult<V03State> {
        self.calculate_state_for_id(self.get_meta_last_block_in_db()?)
    }

    pub fn put_next_breakpoint(&self) -> DbResult<()> {
        let last_block = self.get_meta_last_block_in_db()?;
        let next_breakpoint_id = self
            .get_meta_last_breakpoint_id()?
            .checked_add(1)
            .expect("Reached maximum breakpoint id");
        let block_to_break_id = next_breakpoint_id
            .checked_mul(u64::from(BREAKPOINT_INTERVAL))
            .expect("Reached maximum breakpoint id");

        if block_to_break_id <= last_block {
            let next_breakpoint = self.calculate_state_for_id(block_to_break_id)?;

            self.put_breakpoint(next_breakpoint_id, &next_breakpoint)?;
            self.put_meta_last_breakpoint_id(next_breakpoint_id)
        } else {
            Err(DbError::db_interaction_error(
                "Breakpoint not yet achieved".to_owned(),
            ))
        }
    }

    // Mappings

    pub fn get_block_id_by_hash(&self, hash: [u8; 32]) -> DbResult<Option<u64>> {
        let cf_hti = self.hash_to_id_column();
        let res = self
            .db
            .get_cf(
                &cf_hti,
                borsh::to_vec(&hash).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize block hash".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(Some(borsh::from_slice::<u64>(&data).map_err(|serr| {
                DbError::borsh_cast_message(serr, Some("Failed to deserialize block id".to_owned()))
            })?))
        } else {
            Ok(None)
        }
    }

    pub fn get_block_id_by_tx_hash(&self, tx_hash: [u8; 32]) -> DbResult<Option<u64>> {
        let cf_tti = self.tx_hash_to_id_column();
        let res = self
            .db
            .get_cf(
                &cf_tti,
                borsh::to_vec(&tx_hash).map_err(|err| {
                    DbError::borsh_cast_message(
                        err,
                        Some("Failed to serialize transaction hash".to_owned()),
                    )
                })?,
            )
            .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

        if let Some(data) = res {
            Ok(Some(borsh::from_slice::<u64>(&data).map_err(|serr| {
                DbError::borsh_cast_message(serr, Some("Failed to deserialize block id".to_owned()))
            })?))
        } else {
            Ok(None)
        }
    }

    // Accounts meta

    fn update_acc_meta_batch(
        &self,
        acc_id: [u8; 32],
        num_tx: u64,
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        let cf_ameta = self.account_meta_column();

        write_batch.put_cf(
            &cf_ameta,
            borsh::to_vec(&acc_id).map_err(|err| {
                DbError::borsh_cast_message(err, Some("Failed to serialize account id".to_owned()))
            })?,
            borsh::to_vec(&num_tx).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to serialize acc metadata".to_owned()),
                )
            })?,
        );

        Ok(())
    }

    fn get_acc_meta_num_tx(&self, acc_id: [u8; 32]) -> DbResult<Option<u64>> {
        let cf_ameta = self.account_meta_column();
        let res = self.db.get_cf(&cf_ameta, acc_id).map_err(|rerr| {
            DbError::rocksdb_cast_message(rerr, Some("Failed to read from acc meta cf".to_owned()))
        })?;

        res.map(|data| {
            borsh::from_slice::<u64>(&data).map_err(|serr| {
                DbError::borsh_cast_message(serr, Some("Failed to deserialize num tx".to_owned()))
            })
        })
        .transpose()
    }

    // Account

    pub fn put_account_transactions(
        &self,
        acc_id: [u8; 32],
        tx_hashes: &[[u8; 32]],
    ) -> DbResult<()> {
        let acc_num_tx = self.get_acc_meta_num_tx(acc_id)?.unwrap_or(0);
        let cf_att = self.account_id_to_tx_hash_column();
        let mut write_batch = WriteBatch::new();

        for (tx_id, tx_hash) in tx_hashes.iter().enumerate() {
            let put_id = acc_num_tx
                .checked_add(
                    u64::try_from(tx_id)
                        .expect("Transaction number for account expected to fit in u64"),
                )
                .expect("Reached maximum number of transactions for account");

            let mut prefix = borsh::to_vec(&acc_id).map_err(|berr| {
                DbError::borsh_cast_message(berr, Some("Failed to serialize account id".to_owned()))
            })?;
            let suffix = borsh::to_vec(&put_id).map_err(|berr| {
                DbError::borsh_cast_message(berr, Some("Failed to serialize tx id".to_owned()))
            })?;

            prefix.extend_from_slice(&suffix);

            write_batch.put_cf(
                &cf_att,
                prefix,
                borsh::to_vec(tx_hash).map_err(|berr| {
                    DbError::borsh_cast_message(
                        berr,
                        Some("Failed to serialize tx hash".to_owned()),
                    )
                })?,
            );
        }

        self.update_acc_meta_batch(
            acc_id,
            acc_num_tx
                .checked_add(
                    u64::try_from(tx_hashes.len())
                        .expect("Number of transactions expected to fit in u64"),
                )
                .expect("Reached maximum number of transactions for account"),
            &mut write_batch,
        )?;

        self.db.write(write_batch).map_err(|rerr| {
            DbError::rocksdb_cast_message(rerr, Some("Failed to write batch".to_owned()))
        })
    }

    fn get_acc_transaction_hashes(
        &self,
        acc_id: [u8; 32],
        offset: u64,
        limit: u64,
    ) -> DbResult<Vec<[u8; 32]>> {
        let cf_att = self.account_id_to_tx_hash_column();
        let mut tx_batch = vec![];

        // ToDo: Multi get this

        for tx_id in offset..(offset.saturating_add(limit)) {
            let mut prefix = borsh::to_vec(&acc_id).map_err(|berr| {
                DbError::borsh_cast_message(berr, Some("Failed to serialize account id".to_owned()))
            })?;
            let suffix = borsh::to_vec(&tx_id).map_err(|berr| {
                DbError::borsh_cast_message(berr, Some("Failed to serialize tx id".to_owned()))
            })?;

            prefix.extend_from_slice(&suffix);

            let res = self
                .db
                .get_cf(&cf_att, prefix)
                .map_err(|rerr| DbError::rocksdb_cast_message(rerr, None))?;

            let tx_hash = if let Some(data) = res {
                Ok(borsh::from_slice::<[u8; 32]>(&data).map_err(|serr| {
                    DbError::borsh_cast_message(
                        serr,
                        Some("Failed to deserialize tx_hash".to_owned()),
                    )
                })?)
            } else {
                // Tx hash not found, assuming that previous one was the last
                break;
            }?;

            tx_batch.push(tx_hash);
        }

        Ok(tx_batch)
    }

    pub fn get_acc_transactions(
        &self,
        acc_id: [u8; 32],
        offset: u64,
        limit: u64,
    ) -> DbResult<Vec<NSSATransaction>> {
        let mut tx_batch = vec![];

        for tx_hash in self.get_acc_transaction_hashes(acc_id, offset, limit)? {
            let block_id = self.get_block_id_by_tx_hash(tx_hash)?.ok_or_else(|| {
                DbError::db_interaction_error(format!(
                    "Block id not found for tx hash {tx_hash:#?}"
                ))
            })?;
            let block = self.get_block(block_id)?.ok_or_else(|| {
                DbError::db_interaction_error(format!("Block with id {block_id} not found"))
            })?;

            let transaction = block
                .body
                .transactions
                .iter()
                .find(|tx| tx.hash().0 == tx_hash)
                .ok_or_else(|| {
                    DbError::db_interaction_error(format!(
                        "Missing transaction in block {} with hash {:#?}",
                        block.header.block_id, tx_hash
                    ))
                })?;

            tx_batch.push(transaction.clone());
        }

        Ok(tx_batch)
    }
}

fn closest_breakpoint_id(block_id: u64) -> u64 {
    block_id
        .saturating_sub(1)
        .checked_div(u64::from(BREAKPOINT_INTERVAL))
        .expect("Breakpoint interval is not zero")
}

#[cfg(test)]
mod tests {
    #![expect(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

    use nssa::AccountId;
    use tempfile::tempdir;

    use super::*;

    fn genesis_block() -> Block {
        common::test_utils::produce_dummy_block(1, None, vec![])
    }

    fn acc1() -> AccountId {
        AccountId::new([
            148, 179, 206, 253, 199, 51, 82, 86, 232, 2, 152, 122, 80, 243, 54, 207, 237, 112, 83,
            153, 44, 59, 204, 49, 128, 84, 160, 227, 216, 149, 97, 102,
        ])
    }

    fn acc2() -> AccountId {
        AccountId::new([
            30, 145, 107, 3, 207, 73, 192, 230, 160, 63, 238, 207, 18, 69, 54, 216, 103, 244, 92,
            94, 124, 248, 42, 16, 141, 19, 119, 18, 14, 226, 140, 204,
        ])
    }

    fn acc1_sign_key() -> nssa::PrivateKey {
        nssa::PrivateKey::try_new([1; 32]).unwrap()
    }

    fn acc2_sign_key() -> nssa::PrivateKey {
        nssa::PrivateKey::try_new([2; 32]).unwrap()
    }

    fn initial_state() -> V03State {
        nssa::V03State::new_with_genesis_accounts(&[(acc1(), 10000), (acc2(), 20000)], &[])
    }

    fn transfer(amount: u128, nonce: u128, direction: bool) -> NSSATransaction {
        let from;
        let to;
        let sign_key = if direction {
            from = acc1();
            to = acc2();
            acc1_sign_key()
        } else {
            from = acc2();
            to = acc1();
            acc2_sign_key()
        };

        common::test_utils::create_transaction_native_token_transfer(
            from, nonce, to, amount, &sign_key,
        )
    }

    #[test]
    fn start_db() {
        let temp_dir = tempdir().unwrap();
        let temdir_path = temp_dir.path();

        let dbio =
            RocksDBIO::open_or_create(temdir_path, &genesis_block(), &initial_state()).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let first_id = dbio.get_meta_first_block_in_db().unwrap();
        let is_first_set = dbio.get_meta_is_first_block_set().unwrap();
        let last_br_id = dbio.get_meta_last_breakpoint_id().unwrap();
        let last_block = dbio.get_block(1).unwrap().unwrap();
        let breakpoint = dbio.get_breakpoint(0).unwrap();
        let final_state = dbio.final_state().unwrap();

        assert_eq!(last_id, 1);
        assert_eq!(first_id, 1);
        assert!(is_first_set);
        assert_eq!(last_br_id, 0);
        assert_eq!(last_block.header.hash, genesis_block().header.hash);
        assert_eq!(
            breakpoint.get_account_by_id(acc1()),
            final_state.get_account_by_id(acc1())
        );
        assert_eq!(
            breakpoint.get_account_by_id(acc2()),
            final_state.get_account_by_id(acc2())
        );
    }

    #[test]
    fn one_block_insertion() {
        let temp_dir = tempdir().unwrap();
        let temdir_path = temp_dir.path();

        let dbio =
            RocksDBIO::open_or_create(temdir_path, &genesis_block(), &initial_state()).unwrap();

        let prev_hash = genesis_block().header.hash;
        let transfer_tx = transfer(1, 0, true);
        let block = common::test_utils::produce_dummy_block(2, Some(prev_hash), vec![transfer_tx]);

        dbio.put_block(&block, [1; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let first_id = dbio.get_meta_first_block_in_db().unwrap();
        let is_first_set = dbio.get_meta_is_first_block_set().unwrap();
        let last_br_id = dbio.get_meta_last_breakpoint_id().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();
        let breakpoint = dbio.get_breakpoint(0).unwrap();
        let final_state = dbio.final_state().unwrap();

        assert_eq!(last_id, 2);
        assert_eq!(first_id, 1);
        assert!(is_first_set);
        assert_eq!(last_br_id, 0);
        assert_ne!(last_block.header.hash, genesis_block().header.hash);
        assert_eq!(
            breakpoint.get_account_by_id(acc1()).balance
                - final_state.get_account_by_id(acc1()).balance,
            1
        );
        assert_eq!(
            final_state.get_account_by_id(acc2()).balance
                - breakpoint.get_account_by_id(acc2()).balance,
            1
        );
    }

    #[test]
    fn new_breakpoint() {
        let temp_dir = tempdir().unwrap();
        let temdir_path = temp_dir.path();

        let dbio =
            RocksDBIO::open_or_create(temdir_path, &genesis_block(), &initial_state()).unwrap();

        for i in 1..BREAKPOINT_INTERVAL {
            let last_id = dbio.get_meta_last_block_in_db().unwrap();
            let last_block = dbio.get_block(last_id).unwrap().unwrap();

            let prev_hash = last_block.header.hash;
            let transfer_tx = transfer(1, u128::from(i - 1), true);
            let block = common::test_utils::produce_dummy_block(
                u64::from(i + 1),
                Some(prev_hash),
                vec![transfer_tx],
            );
            dbio.put_block(&block, [i; 32]).unwrap();
        }

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let first_id = dbio.get_meta_first_block_in_db().unwrap();
        let is_first_set = dbio.get_meta_is_first_block_set().unwrap();
        let last_br_id = dbio.get_meta_last_breakpoint_id().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();
        let prev_breakpoint = dbio.get_breakpoint(0).unwrap();
        let breakpoint = dbio.get_breakpoint(1).unwrap();
        let final_state = dbio.final_state().unwrap();

        assert_eq!(last_id, 100);
        assert_eq!(first_id, 1);
        assert!(is_first_set);
        assert_eq!(last_br_id, 1);
        assert_ne!(last_block.header.hash, genesis_block().header.hash);
        assert_eq!(
            prev_breakpoint.get_account_by_id(acc1()).balance
                - final_state.get_account_by_id(acc1()).balance,
            99
        );
        assert_eq!(
            final_state.get_account_by_id(acc2()).balance
                - prev_breakpoint.get_account_by_id(acc2()).balance,
            99
        );
        assert_eq!(
            breakpoint.get_account_by_id(acc1()),
            final_state.get_account_by_id(acc1())
        );
        assert_eq!(
            breakpoint.get_account_by_id(acc2()),
            final_state.get_account_by_id(acc2())
        );
    }

    #[test]
    fn simple_maps() {
        let temp_dir = tempdir().unwrap();
        let temdir_path = temp_dir.path();

        let dbio =
            RocksDBIO::open_or_create(temdir_path, &genesis_block(), &initial_state()).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx = transfer(1, 0, true);
        let block = common::test_utils::produce_dummy_block(2, Some(prev_hash), vec![transfer_tx]);

        let control_hash1 = block.header.hash;

        dbio.put_block(&block, [1; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx = transfer(1, 1, true);
        let block = common::test_utils::produce_dummy_block(3, Some(prev_hash), vec![transfer_tx]);

        let control_hash2 = block.header.hash;

        dbio.put_block(&block, [2; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx = transfer(1, 2, true);

        let control_tx_hash1 = transfer_tx.hash();

        let block = common::test_utils::produce_dummy_block(4, Some(prev_hash), vec![transfer_tx]);
        dbio.put_block(&block, [3; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx = transfer(1, 3, true);

        let control_tx_hash2 = transfer_tx.hash();

        let block = common::test_utils::produce_dummy_block(5, Some(prev_hash), vec![transfer_tx]);
        dbio.put_block(&block, [4; 32]).unwrap();

        let control_block_id1 = dbio.get_block_id_by_hash(control_hash1.0).unwrap().unwrap();
        let control_block_id2 = dbio.get_block_id_by_hash(control_hash2.0).unwrap().unwrap();
        let control_block_id3 = dbio
            .get_block_id_by_tx_hash(control_tx_hash1.0)
            .unwrap()
            .unwrap();
        let control_block_id4 = dbio
            .get_block_id_by_tx_hash(control_tx_hash2.0)
            .unwrap()
            .unwrap();

        assert_eq!(control_block_id1, 2);
        assert_eq!(control_block_id2, 3);
        assert_eq!(control_block_id3, 4);
        assert_eq!(control_block_id4, 5);
    }

    #[test]
    fn block_batch() {
        let temp_dir = tempdir().unwrap();
        let temdir_path = temp_dir.path();

        let mut block_res = vec![];

        let dbio =
            RocksDBIO::open_or_create(temdir_path, &genesis_block(), &initial_state()).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx = transfer(1, 0, true);
        let block = common::test_utils::produce_dummy_block(2, Some(prev_hash), vec![transfer_tx]);

        block_res.push(block.clone());
        dbio.put_block(&block, [1; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx = transfer(1, 1, true);
        let block = common::test_utils::produce_dummy_block(3, Some(prev_hash), vec![transfer_tx]);

        block_res.push(block.clone());
        dbio.put_block(&block, [2; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx = transfer(1, 2, true);

        let block = common::test_utils::produce_dummy_block(4, Some(prev_hash), vec![transfer_tx]);
        block_res.push(block.clone());
        dbio.put_block(&block, [3; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx = transfer(1, 3, true);

        let block = common::test_utils::produce_dummy_block(5, Some(prev_hash), vec![transfer_tx]);
        block_res.push(block.clone());
        dbio.put_block(&block, [4; 32]).unwrap();

        let block_hashes_mem: Vec<[u8; 32]> =
            block_res.into_iter().map(|bl| bl.header.hash.0).collect();

        // Get blocks before ID 6 (i.e., starting from 5 going backwards), limit 4
        // This should return blocks 5, 4, 3, 2 in descending order
        let mut batch_res = dbio.get_block_batch(Some(6), 4).unwrap();
        batch_res.reverse(); // Reverse to match ascending order for comparison

        let block_hashes_db: Vec<[u8; 32]> =
            batch_res.into_iter().map(|bl| bl.header.hash.0).collect();

        assert_eq!(block_hashes_mem, block_hashes_db);

        let block_hashes_mem_limited = &block_hashes_mem[1..];

        // Get blocks before ID 6, limit 3
        // This should return blocks 5, 4, 3 in descending order
        let mut batch_res_limited = dbio.get_block_batch(Some(6), 3).unwrap();
        batch_res_limited.reverse(); // Reverse to match ascending order for comparison

        let block_hashes_db_limited: Vec<[u8; 32]> = batch_res_limited
            .into_iter()
            .map(|bl| bl.header.hash.0)
            .collect();

        assert_eq!(block_hashes_mem_limited, block_hashes_db_limited.as_slice());
    }

    #[test]
    fn account_map() {
        let temp_dir = tempdir().unwrap();
        let temdir_path = temp_dir.path();

        let mut tx_hash_res = vec![];

        let dbio =
            RocksDBIO::open_or_create(temdir_path, &genesis_block(), &initial_state()).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx = transfer(1, 0, true);

        tx_hash_res.push(transfer_tx.hash().0);

        let block = common::test_utils::produce_dummy_block(2, Some(prev_hash), vec![transfer_tx]);

        dbio.put_block(&block, [1; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx = transfer(1, 1, true);

        tx_hash_res.push(transfer_tx.hash().0);

        let block = common::test_utils::produce_dummy_block(3, Some(prev_hash), vec![transfer_tx]);

        dbio.put_block(&block, [2; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx = transfer(1, 2, true);

        tx_hash_res.push(transfer_tx.hash().0);

        let block = common::test_utils::produce_dummy_block(4, Some(prev_hash), vec![transfer_tx]);

        dbio.put_block(&block, [3; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx = transfer(1, 3, true);

        tx_hash_res.push(transfer_tx.hash().0);

        let block = common::test_utils::produce_dummy_block(5, Some(prev_hash), vec![transfer_tx]);

        dbio.put_block(&block, [4; 32]).unwrap();

        let acc1_tx = dbio.get_acc_transactions(*acc1().value(), 0, 4).unwrap();
        let acc1_tx_hashes: Vec<[u8; 32]> = acc1_tx.into_iter().map(|tx| tx.hash().0).collect();

        assert_eq!(acc1_tx_hashes, tx_hash_res);

        let acc1_tx_limited = dbio.get_acc_transactions(*acc1().value(), 1, 4).unwrap();
        let acc1_tx_limited_hashes: Vec<[u8; 32]> =
            acc1_tx_limited.into_iter().map(|tx| tx.hash().0).collect();

        assert_eq!(acc1_tx_limited_hashes.as_slice(), &tx_hash_res[1..]);
    }
}
