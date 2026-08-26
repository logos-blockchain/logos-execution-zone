use std::{path::Path, sync::Arc};

use common::block::Block;
use lee::V03State;
use log::warn;
use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, MultiThreaded, Options,
};

use crate::{BREAKPOINT_INTERVAL, CF_BLOCK_NAME, CF_META_NAME, DBIO, DbResult, error::DbError};

pub mod indexer_cells;
pub mod read_multiple;
pub mod read_once;
pub mod write_atomic;
pub mod write_non_atomic;

/// Key base for storing metainformation about id of last observed L1 lib header in db.
pub const DB_META_LAST_OBSERVED_L1_LIB_HEADER_ID_IN_DB_KEY: &str =
    "last_observed_l1_lib_header_in_db";
/// Key base for storing the zone-sdk indexer cursor (opaque bytes).
pub const DB_META_ZONE_SDK_INDEXER_CURSOR_KEY: &str = "zone_sdk_indexer_cursor";
/// Key base for storing the persisted `Option<StallReason>` diagnostic record (opaque JSON bytes).
pub const DB_META_STALL_REASON_KEY: &str = "stall_reason";
/// Key base for storing the persisted cross-zone halt record (opaque JSON bytes).
pub const DB_META_CROSS_ZONE_HALT_KEY: &str = "cross_zone_halt";
/// Key base for storing the L1 inscription slot of the tip block.
pub const DB_META_TIP_SLOT_KEY: &str = "tip_slot";

/// Cell name for a breakpoint.
pub const BREAKPOINT_CELL_NAME: &str = "breakpoint";
/// Cell name for a block hash to block id map.
pub const BLOCK_HASH_CELL_NAME: &str = "block hash";
/// Cell name for a tx hash to block id map.
pub const TX_HASH_CELL_NAME: &str = "tx hash";
/// Cell name for a account number of transactions.
pub const ACC_NUM_CELL_NAME: &str = "acc id";

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

pub struct RocksDBIO {
    pub db: DBWithThreadMode<MultiThreaded>,
}

impl DBIO for RocksDBIO {
    fn db(&self) -> &DBWithThreadMode<MultiThreaded> {
        &self.db
    }
}

impl RocksDBIO {
    // TODO: Remove initial state when it will be included in genesis block
    pub fn open_or_create(path: &Path, initial_state: &V03State) -> DbResult<Self> {
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

        // Seed the genesis snapshot once; reopening must not clobber it.
        if dbio.get_breakpoint_opt(0)?.is_none() {
            dbio.put_breakpoint(0, initial_state)?;
        }

        Ok(dbio)
    }

    pub fn destroy(path: &Path) -> DbResult<()> {
        let db_opts = Options::default();
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

    pub fn breakpoint_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(CF_BREAKPOINT_NAME)
            .expect("Breakpoint column should exist")
    }

    pub fn hash_to_id_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(CF_HASH_TO_ID)
            .expect("Hash to id map column should exist")
    }

    pub fn tx_hash_to_id_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(CF_TX_TO_ID)
            .expect("Tx hash to id map column should exist")
    }

    pub fn account_id_to_tx_hash_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(CF_ACC_TO_TX)
            .expect("Account id to tx map column should exist")
    }

    pub fn account_meta_column(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(CF_ACC_META)
            .expect("Account meta column should exist")
    }

    // State

    pub fn calculate_state_for_id(&self, block_id: u64) -> DbResult<V03State> {
        let last_block_id = self.get_meta_last_block_id_in_db()?.unwrap_or(0);

        if block_id > last_block_id {
            return Err(DbError::db_interaction_error(
                "Block on this id not found".to_owned(),
            ));
        }

        // walk down to the nearest snapshot that exists
        let target = closest_breakpoint_id(block_id);
        let mut br_id = target;
        let mut state = loop {
            match self.get_breakpoint_opt(br_id)? {
                Some(state) => break state,
                None if br_id == 0 => {
                    return Err(DbError::db_interaction_error(
                        "Breakpoint 0 is missing".to_owned(),
                    ));
                }
                None => {
                    br_id = br_id
                        .checked_sub(1)
                        .expect("breakpoint_id > 0 checked above");
                }
            }
        };
        if br_id < target {
            warn!(
                "Breakpoint {target} missing; replaying from breakpoint {br_id} for block {block_id}"
            );
        }

        let start = u64::from(BREAKPOINT_INTERVAL)
            .checked_mul(br_id)
            .expect("Reached maximum breakpoint id");

        for block in self.get_block_batch_seq(
            start.checked_add(1).expect("Will be lesser that u64::MAX")..=block_id,
        )? {
            apply_block_transactions(&block, &mut state)?;
        }

        Ok(state)
    }

    pub fn final_state(&self) -> DbResult<V03State> {
        let last_block_id = self.get_meta_last_block_id_in_db()?.unwrap_or(0);
        self.calculate_state_for_id(last_block_id)
    }
}

fn apply_block_transactions(block: &Block, state: &mut V03State) -> DbResult<()> {
    // The indexer replays through the same transition the sequencer and
    // validators use, so the fee settlement arithmetic exists exactly once.
    chain_state::apply::apply_block_to_state(block, state)
        .map_err(|err| DbError::db_interaction_error(format!("block replay failed: {err}")))
}

fn closest_breakpoint_id(block_id: u64) -> u64 {
    block_id
        .saturating_sub(1)
        .checked_div(u64::from(BREAKPOINT_INTERVAL))
        .expect("Breakpoint interval is not zero")
}

#[expect(clippy::shadow_unrelated, reason = "Fine for tests")]
#[cfg(test)]
mod tests;
