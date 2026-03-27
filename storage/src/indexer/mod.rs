use std::{path::Path, sync::Arc};

use common::block::Block;
use nssa::V03State;
use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, MultiThreaded, Options,
};

use crate::error::DbError;

pub mod read_multiple;
pub mod read_once;
pub mod write_atomic;
pub mod write_non_atomic;

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
            dbio.put_meta_first_block_in_db_batch(genesis_block)?;
            dbio.put_meta_is_first_block_set()?;

            // First breakpoint setup
            dbio.put_breakpoint(0, initial_state)?;
            dbio.put_meta_last_breakpoint_id(0)?;
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

            for block in self.get_block_batch_seq(
                start.checked_add(1).expect("Will be lesser that u64::MAX")..=block_id,
            )? {
                for transaction in block.body.transactions {
                    transaction
                        .transaction_stateless_check()
                        .map_err(|err| {
                            DbError::db_interaction_error(format!(
                                "transaction pre check failed with err {err:?}"
                            ))
                        })?
                        .execute_check_on_state(&mut breakpoint, block.header.block_id)
                        .map_err(|err| {
                            DbError::db_interaction_error(format!(
                                "transaction execution failed with err {err:?}"
                            ))
                        })?;
                }
            }

            Ok(breakpoint)
        } else {
            Err(DbError::db_interaction_error(
                "Block on this id not found".to_owned(),
            ))
        }
    }

    pub fn final_state(&self) -> DbResult<V03State> {
        self.calculate_state_for_id(self.get_meta_last_block_in_db()?)
    }
}

fn closest_breakpoint_id(block_id: u64) -> u64 {
    block_id
        .saturating_sub(1)
        .checked_div(u64::from(BREAKPOINT_INTERVAL))
        .expect("Breakpoint interval is not zero")
}

#[expect(clippy::shadow_unrelated, reason = "Fine for tests")]
#[cfg(test)]
mod tests {
    use nssa::{AccountId, PublicKey};
    use tempfile::tempdir;

    use super::*;

    fn genesis_block() -> Block {
        common::test_utils::produce_dummy_block(1, None, vec![])
    }

    fn acc1_sign_key() -> nssa::PrivateKey {
        nssa::PrivateKey::try_new([1; 32]).unwrap()
    }

    fn acc2_sign_key() -> nssa::PrivateKey {
        nssa::PrivateKey::try_new([2; 32]).unwrap()
    }

    fn acc1() -> AccountId {
        AccountId::from(&PublicKey::new_from_private_key(&acc1_sign_key()))
    }

    fn acc2() -> AccountId {
        AccountId::from(&PublicKey::new_from_private_key(&acc2_sign_key()))
    }

    #[test]
    fn start_db() {
        let temp_dir = tempdir().unwrap();
        let temdir_path = temp_dir.path();

        let dbio = RocksDBIO::open_or_create(
            temdir_path,
            &genesis_block(),
            &nssa::V03State::new_with_genesis_accounts(&[(acc1(), 10000), (acc2(), 20000)], &[]),
        )
        .unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let first_id = dbio.get_meta_first_block_in_db().unwrap();
        let is_first_set = dbio.get_meta_is_first_block_set().unwrap();
        let last_observed_l1_header = dbio.get_meta_last_observed_l1_lib_header_in_db().unwrap();
        let last_br_id = dbio.get_meta_last_breakpoint_id().unwrap();
        let last_block = dbio.get_block(1).unwrap().unwrap();
        let breakpoint = dbio.get_breakpoint(0).unwrap();
        let final_state = dbio.final_state().unwrap();

        assert_eq!(last_id, 1);
        assert_eq!(first_id, 1);
        assert_eq!(last_observed_l1_header, None);
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

        let dbio = RocksDBIO::open_or_create(
            temdir_path,
            &genesis_block(),
            &nssa::V03State::new_with_genesis_accounts(&[(acc1(), 10000), (acc2(), 20000)], &[]),
        )
        .unwrap();

        let prev_hash = genesis_block().header.hash;
        let from = acc1();
        let to = acc2();
        let sign_key = acc1_sign_key();

        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 0, to, 1, &sign_key);
        let block = common::test_utils::produce_dummy_block(2, Some(prev_hash), vec![transfer_tx]);

        dbio.put_block(&block, [1; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let first_id = dbio.get_meta_first_block_in_db().unwrap();
        let last_observed_l1_header = dbio
            .get_meta_last_observed_l1_lib_header_in_db()
            .unwrap()
            .unwrap();
        let is_first_set = dbio.get_meta_is_first_block_set().unwrap();
        let last_br_id = dbio.get_meta_last_breakpoint_id().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();
        let breakpoint = dbio.get_breakpoint(0).unwrap();
        let final_state = dbio.final_state().unwrap();

        assert_eq!(last_id, 2);
        assert_eq!(first_id, 1);
        assert_eq!(last_observed_l1_header, [1; 32]);
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

        let dbio = RocksDBIO::open_or_create(
            temdir_path,
            &genesis_block(),
            &nssa::V03State::new_with_genesis_accounts(&[(acc1(), 10000), (acc2(), 20000)], &[]),
        )
        .unwrap();

        let from = acc1();
        let to = acc2();
        let sign_key = acc1_sign_key();

        for i in 1..=BREAKPOINT_INTERVAL {
            let last_id = dbio.get_meta_last_block_in_db().unwrap();
            let last_block = dbio.get_block(last_id).unwrap().unwrap();

            let prev_hash = last_block.header.hash;

            let transfer_tx = common::test_utils::create_transaction_native_token_transfer(
                from,
                (i - 1).into(),
                to,
                1,
                &sign_key,
            );
            let block = common::test_utils::produce_dummy_block(
                (i + 1).into(),
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

        assert_eq!(last_id, 101);
        assert_eq!(first_id, 1);
        assert!(is_first_set);
        assert_eq!(last_br_id, 1);
        assert_ne!(last_block.header.hash, genesis_block().header.hash);
        assert_eq!(
            prev_breakpoint.get_account_by_id(acc1()).balance
                - final_state.get_account_by_id(acc1()).balance,
            100
        );
        assert_eq!(
            final_state.get_account_by_id(acc2()).balance
                - prev_breakpoint.get_account_by_id(acc2()).balance,
            100
        );
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
    fn simple_maps() {
        let temp_dir = tempdir().unwrap();
        let temdir_path = temp_dir.path();

        let dbio = RocksDBIO::open_or_create(
            temdir_path,
            &genesis_block(),
            &nssa::V03State::new_with_genesis_accounts(&[(acc1(), 10000), (acc2(), 20000)], &[]),
        )
        .unwrap();

        let from = acc1();
        let to = acc2();
        let sign_key = acc1_sign_key();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 0, to, 1, &sign_key);
        let block = common::test_utils::produce_dummy_block(2, Some(prev_hash), vec![transfer_tx]);

        let control_hash1 = block.header.hash;

        dbio.put_block(&block, [1; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 1, to, 1, &sign_key);
        let block = common::test_utils::produce_dummy_block(3, Some(prev_hash), vec![transfer_tx]);

        let control_hash2 = block.header.hash;

        dbio.put_block(&block, [2; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 2, to, 1, &sign_key);

        let control_tx_hash1 = transfer_tx.hash();

        let block = common::test_utils::produce_dummy_block(4, Some(prev_hash), vec![transfer_tx]);
        dbio.put_block(&block, [3; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 3, to, 1, &sign_key);

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

        let dbio = RocksDBIO::open_or_create(
            temdir_path,
            &genesis_block(),
            &nssa::V03State::new_with_genesis_accounts(&[(acc1(), 10000), (acc2(), 20000)], &[]),
        )
        .unwrap();

        let from = acc1();
        let to = acc2();
        let sign_key = acc1_sign_key();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 0, to, 1, &sign_key);
        let block = common::test_utils::produce_dummy_block(2, Some(prev_hash), vec![transfer_tx]);

        block_res.push(block.clone());
        dbio.put_block(&block, [1; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 1, to, 1, &sign_key);
        let block = common::test_utils::produce_dummy_block(3, Some(prev_hash), vec![transfer_tx]);

        block_res.push(block.clone());
        dbio.put_block(&block, [2; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 2, to, 1, &sign_key);

        let block = common::test_utils::produce_dummy_block(4, Some(prev_hash), vec![transfer_tx]);
        block_res.push(block.clone());
        dbio.put_block(&block, [3; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 3, to, 1, &sign_key);

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

        let block_batch_seq = dbio.get_block_batch_seq(1..=5).unwrap();
        let block_batch_ids = block_batch_seq
            .into_iter()
            .map(|block| block.header.block_id)
            .collect::<Vec<_>>();

        assert_eq!(block_batch_ids, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn account_map() {
        let temp_dir = tempdir().unwrap();
        let temdir_path = temp_dir.path();

        let dbio = RocksDBIO::open_or_create(
            temdir_path,
            &genesis_block(),
            &nssa::V03State::new_with_genesis_accounts(&[(acc1(), 10000), (acc2(), 20000)], &[]),
        )
        .unwrap();

        let from = acc1();
        let to = acc2();
        let sign_key = acc1_sign_key();

        let mut tx_hash_res = vec![];

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx1 =
            common::test_utils::create_transaction_native_token_transfer(from, 0, to, 1, &sign_key);
        let transfer_tx2 =
            common::test_utils::create_transaction_native_token_transfer(from, 1, to, 1, &sign_key);
        tx_hash_res.push(transfer_tx1.hash().0);
        tx_hash_res.push(transfer_tx2.hash().0);

        let block = common::test_utils::produce_dummy_block(
            2,
            Some(prev_hash),
            vec![transfer_tx1, transfer_tx2],
        );

        dbio.put_block(&block, [1; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx1 =
            common::test_utils::create_transaction_native_token_transfer(from, 2, to, 1, &sign_key);
        let transfer_tx2 =
            common::test_utils::create_transaction_native_token_transfer(from, 3, to, 1, &sign_key);
        tx_hash_res.push(transfer_tx1.hash().0);
        tx_hash_res.push(transfer_tx2.hash().0);

        let block = common::test_utils::produce_dummy_block(
            3,
            Some(prev_hash),
            vec![transfer_tx1, transfer_tx2],
        );

        dbio.put_block(&block, [2; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx1 =
            common::test_utils::create_transaction_native_token_transfer(from, 4, to, 1, &sign_key);
        let transfer_tx2 =
            common::test_utils::create_transaction_native_token_transfer(from, 5, to, 1, &sign_key);
        tx_hash_res.push(transfer_tx1.hash().0);
        tx_hash_res.push(transfer_tx2.hash().0);

        let block = common::test_utils::produce_dummy_block(
            4,
            Some(prev_hash),
            vec![transfer_tx1, transfer_tx2],
        );

        dbio.put_block(&block, [3; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_in_db().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 6, to, 1, &sign_key);
        tx_hash_res.push(transfer_tx.hash().0);

        let block = common::test_utils::produce_dummy_block(5, Some(prev_hash), vec![transfer_tx]);

        dbio.put_block(&block, [4; 32]).unwrap();

        let acc1_tx = dbio.get_acc_transactions(*acc1().value(), 0, 7).unwrap();
        let acc1_tx_hashes: Vec<[u8; 32]> = acc1_tx.into_iter().map(|tx| tx.hash().0).collect();

        assert_eq!(acc1_tx_hashes, tx_hash_res);

        let acc1_tx_limited = dbio.get_acc_transactions(*acc1().value(), 1, 4).unwrap();
        let acc1_tx_limited_hashes: Vec<[u8; 32]> =
            acc1_tx_limited.into_iter().map(|tx| tx.hash().0).collect();

        assert_eq!(acc1_tx_limited_hashes.as_slice(), &tx_hash_res[1..5]);
    }
}
