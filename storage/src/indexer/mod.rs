use std::{path::Path, sync::Arc};

use common::{
    block::Block,
    transaction::{NSSATransaction, clock_invocation},
};
use nssa::{GENESIS_BLOCK_ID, V03State, ValidatedStateDiff};
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
/// Key base for storing metainformation about the last breakpoint.
pub const DB_META_LAST_BREAKPOINT_ID: &str = "last_breakpoint_id";
/// Key base for storing the zone-sdk indexer cursor (opaque bytes).
pub const DB_META_ZONE_SDK_INDEXER_CURSOR_KEY: &str = "zone_sdk_indexer_cursor";

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

        // First breakpoint setup
        dbio.put_breakpoint(0, initial_state)?;
        dbio.put_meta_last_breakpoint_id(0)?;

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

        let br_id = closest_breakpoint_id(block_id);
        let mut breakpoint = self.get_breakpoint(br_id)?;

        let start = u64::from(BREAKPOINT_INTERVAL)
            .checked_mul(br_id)
            .expect("Reached maximum breakpoint id");

        for mut block in self.get_block_batch_seq(
            start.checked_add(1).expect("Will be lesser that u64::MAX")..=block_id,
        )? {
            let expected_clock = NSSATransaction::Public(clock_invocation(block.header.timestamp));

            let clock_tx = block.body.transactions.pop().ok_or_else(|| {
                DbError::db_interaction_error(
                    "Block must contain clock transaction at the end".to_owned(),
                )
            })?;
            let user_txs = block.body.transactions;

            if clock_tx != expected_clock {
                return Err(DbError::db_interaction_error(
                        "Last transaction in block must be the clock invocation for the block timestamp"
                            .to_owned(),
                    ));
            }
            for transaction in user_txs {
                let is_genesis = block.header.block_id == GENESIS_BLOCK_ID;
                if is_genesis {
                    let genesis_tx = match transaction {
                        NSSATransaction::Public(public_tx) => public_tx,
                        NSSATransaction::PrivacyPreserving(_)
                        | NSSATransaction::ProgramDeployment(_) => {
                            return Err(DbError::db_interaction_error(
                                "Genesis block should contain only public transactions".to_owned(),
                            ));
                        }
                    };
                    let state_diff = ValidatedStateDiff::from_public_genesis_transaction(
                        &genesis_tx,
                        &breakpoint,
                    )
                    .map_err(|err| {
                        DbError::db_interaction_error(format!(
                            "Failed to create state diff from genesis transaction with err {err:?}"
                        ))
                    })?;
                    breakpoint.apply_state_diff(state_diff);
                } else {
                    transaction
                        .transaction_stateless_check()
                        .map_err(|err| {
                            DbError::db_interaction_error(format!(
                                "transaction pre check failed with err {err:?}"
                            ))
                        })?
                        .execute_check_on_state(
                            &mut breakpoint,
                            block.header.block_id,
                            block.header.timestamp,
                        )
                        .map_err(|err| {
                            DbError::db_interaction_error(format!(
                                "transaction execution failed with err {err:?}"
                            ))
                        })?;
                }
            }

            let NSSATransaction::Public(clock_public_tx) = clock_tx else {
                return Err(DbError::db_interaction_error(
                    "Clock invocation must be a public transaction".to_owned(),
                ));
            };

            breakpoint
                .transition_from_public_transaction(
                    &clock_public_tx,
                    block.header.block_id,
                    block.header.timestamp,
                )
                .map_err(|err| {
                    DbError::db_interaction_error(format!(
                        "clock transaction execution failed with err {err:?}"
                    ))
                })?;
        }

        Ok(breakpoint)
    }

    pub fn final_state(&self) -> DbResult<V03State> {
        let last_block_id = self.get_meta_last_block_id_in_db()?.unwrap_or(0);
        self.calculate_state_for_id(last_block_id)
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
    use common::test_utils::produce_dummy_block;
    use nssa::{AccountId, PublicKey};
    use tempfile::tempdir;

    use super::*;

    fn genesis_block() -> Block {
        produce_dummy_block(1, None, vec![])
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
            &nssa::V03State::new_with_genesis_accounts(
                &[(acc1(), 10000), (acc2(), 20000)],
                vec![],
                0,
            ),
        )
        .unwrap();

        let last_id = dbio.get_meta_last_block_id_in_db().unwrap();
        let first_id = dbio.get_meta_first_block_id_in_db().unwrap();
        let is_first_set = dbio.get_meta_is_first_block_set().unwrap();
        let last_observed_l1_header = dbio.get_meta_last_observed_l1_lib_header_in_db().unwrap();
        let last_br_id = dbio.get_meta_last_breakpoint_id().unwrap();
        let last_block = dbio.get_block(1).unwrap();
        let breakpoint = dbio.get_breakpoint(0).unwrap();
        let final_state = dbio.final_state().unwrap();

        assert_eq!(last_id, None);
        assert_eq!(first_id, None);
        assert_eq!(last_observed_l1_header, None);
        assert!(!is_first_set);
        assert_eq!(last_br_id, Some(0)); // TODO: Will be None after we remove hardcoded testnet state
        assert!(last_block.is_none());
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
            &nssa::V03State::new_with_genesis_accounts(
                &[(acc1(), 10000), (acc2(), 20000)],
                vec![],
                0,
            ),
        )
        .unwrap();

        let genesis_block = genesis_block();
        dbio.put_block(&genesis_block, [0; 32]).unwrap();

        let prev_hash = genesis_block.header.hash;
        let from = acc1();
        let to = acc2();
        let sign_key = acc1_sign_key();

        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 0, to, 1, &sign_key);
        let block = produce_dummy_block(2, Some(prev_hash), vec![transfer_tx]);

        dbio.put_block(&block, [1; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
        let first_id = dbio.get_meta_first_block_id_in_db().unwrap();
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
        assert_eq!(first_id, Some(1));
        assert_eq!(last_observed_l1_header, [1; 32]);
        assert!(is_first_set);
        assert_eq!(last_br_id, Some(0));
        assert_eq!(last_block.header.hash, block.header.hash);
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
            &nssa::V03State::new_with_genesis_accounts(
                &[(acc1(), 10000), (acc2(), 20000)],
                vec![],
                0,
            ),
        )
        .unwrap();

        let from = acc1();
        let to = acc2();
        let sign_key = acc1_sign_key();

        for i in 1..=BREAKPOINT_INTERVAL + 1 {
            let prev_hash = dbio.get_meta_last_block_id_in_db().unwrap().map(|last_id| {
                let last_block = dbio.get_block(last_id).unwrap().unwrap();
                last_block.header.hash
            });

            let transfer_tx = common::test_utils::create_transaction_native_token_transfer(
                from,
                (i - 1).into(),
                to,
                1,
                &sign_key,
            );
            let block = produce_dummy_block(i.into(), prev_hash, vec![transfer_tx]);
            dbio.put_block(&block, [i; 32]).unwrap();
        }

        let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
        let first_id = dbio.get_meta_first_block_id_in_db().unwrap();
        let is_first_set = dbio.get_meta_is_first_block_set().unwrap();
        let last_br_id = dbio.get_meta_last_breakpoint_id().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();
        let prev_breakpoint = dbio.get_breakpoint(0).unwrap();
        let breakpoint = dbio.get_breakpoint(1).unwrap();
        let final_state = dbio.final_state().unwrap();

        assert_eq!(last_id, 101);
        assert_eq!(first_id, Some(1));
        assert!(is_first_set);
        assert_eq!(last_br_id, Some(1));
        assert_ne!(last_block.header.hash, genesis_block().header.hash);
        assert_eq!(
            prev_breakpoint.get_account_by_id(acc1()).balance
                - final_state.get_account_by_id(acc1()).balance,
            101
        );
        assert_eq!(
            final_state.get_account_by_id(acc2()).balance
                - prev_breakpoint.get_account_by_id(acc2()).balance,
            101
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
            &nssa::V03State::new_with_genesis_accounts(
                &[(acc1(), 10000), (acc2(), 20000)],
                vec![],
                0,
            ),
        )
        .unwrap();

        let from = acc1();
        let to = acc2();
        let sign_key = acc1_sign_key();

        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 0, to, 1, &sign_key);
        let block = produce_dummy_block(1, None, vec![transfer_tx]);

        let control_hash1 = block.header.hash;

        dbio.put_block(&block, [1; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 1, to, 1, &sign_key);
        let block = produce_dummy_block(2, Some(prev_hash), vec![transfer_tx]);

        let control_hash2 = block.header.hash;

        dbio.put_block(&block, [2; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 2, to, 1, &sign_key);

        let control_tx_hash1 = transfer_tx.hash();

        let block = produce_dummy_block(3, Some(prev_hash), vec![transfer_tx]);
        dbio.put_block(&block, [3; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 3, to, 1, &sign_key);

        let control_tx_hash2 = transfer_tx.hash();

        let block = produce_dummy_block(4, Some(prev_hash), vec![transfer_tx]);
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

        assert_eq!(control_block_id1, 1);
        assert_eq!(control_block_id2, 2);
        assert_eq!(control_block_id3, 3);
        assert_eq!(control_block_id4, 4);
    }

    #[test]
    fn block_batch() {
        let temp_dir = tempdir().unwrap();
        let temdir_path = temp_dir.path();

        let mut block_res = vec![];

        let dbio = RocksDBIO::open_or_create(
            temdir_path,
            &nssa::V03State::new_with_genesis_accounts(
                &[(acc1(), 10000), (acc2(), 20000)],
                vec![],
                0,
            ),
        )
        .unwrap();

        let from = acc1();
        let to = acc2();
        let sign_key = acc1_sign_key();

        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 0, to, 1, &sign_key);
        let block = produce_dummy_block(1, None, vec![transfer_tx]);

        block_res.push(block.clone());
        dbio.put_block(&block, [1; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 1, to, 1, &sign_key);
        let block = produce_dummy_block(2, Some(prev_hash), vec![transfer_tx]);

        block_res.push(block.clone());
        dbio.put_block(&block, [2; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 2, to, 1, &sign_key);

        let block = produce_dummy_block(3, Some(prev_hash), vec![transfer_tx]);
        block_res.push(block.clone());
        dbio.put_block(&block, [3; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 3, to, 1, &sign_key);

        let block = produce_dummy_block(4, Some(prev_hash), vec![transfer_tx]);
        block_res.push(block.clone());
        dbio.put_block(&block, [4; 32]).unwrap();

        let block_hashes_mem: Vec<[u8; 32]> =
            block_res.into_iter().map(|bl| bl.header.hash.0).collect();

        // Get blocks before ID 5 (i.e., starting from 4 going backwards), limit 4
        // This should return blocks 4, 3, 2, 1 in descending order
        let mut batch_res = dbio.get_block_batch(Some(5), 4).unwrap();
        batch_res.reverse(); // Reverse to match ascending order for comparison

        let block_hashes_db: Vec<[u8; 32]> =
            batch_res.into_iter().map(|bl| bl.header.hash.0).collect();

        assert_eq!(block_hashes_mem, block_hashes_db);

        let block_hashes_mem_limited = &block_hashes_mem[1..];

        // Get blocks before ID 5, limit 3
        // This should return blocks 4, 3, 2 in descending order
        let mut batch_res_limited = dbio.get_block_batch(Some(5), 3).unwrap();
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

        assert_eq!(block_batch_ids, vec![1, 2, 3, 4]);
    }

    #[test]
    fn account_map() {
        let temp_dir = tempdir().unwrap();
        let temdir_path = temp_dir.path();

        let dbio = RocksDBIO::open_or_create(
            temdir_path,
            &nssa::V03State::new_with_genesis_accounts(
                &[(acc1(), 10000), (acc2(), 20000)],
                vec![],
                0,
            ),
        )
        .unwrap();

        let from = acc1();
        let to = acc2();
        let sign_key = acc1_sign_key();

        let mut tx_hash_res = vec![];

        let transfer_tx1 =
            common::test_utils::create_transaction_native_token_transfer(from, 0, to, 1, &sign_key);
        let transfer_tx2 =
            common::test_utils::create_transaction_native_token_transfer(from, 1, to, 1, &sign_key);
        tx_hash_res.push(transfer_tx1.hash().0);
        tx_hash_res.push(transfer_tx2.hash().0);

        let block = produce_dummy_block(1, None, vec![transfer_tx1, transfer_tx2]);

        dbio.put_block(&block, [1; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx1 =
            common::test_utils::create_transaction_native_token_transfer(from, 2, to, 1, &sign_key);
        let transfer_tx2 =
            common::test_utils::create_transaction_native_token_transfer(from, 3, to, 1, &sign_key);
        tx_hash_res.push(transfer_tx1.hash().0);
        tx_hash_res.push(transfer_tx2.hash().0);

        let block = produce_dummy_block(2, Some(prev_hash), vec![transfer_tx1, transfer_tx2]);

        dbio.put_block(&block, [2; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx1 =
            common::test_utils::create_transaction_native_token_transfer(from, 4, to, 1, &sign_key);
        let transfer_tx2 =
            common::test_utils::create_transaction_native_token_transfer(from, 5, to, 1, &sign_key);
        tx_hash_res.push(transfer_tx1.hash().0);
        tx_hash_res.push(transfer_tx2.hash().0);

        let block = produce_dummy_block(3, Some(prev_hash), vec![transfer_tx1, transfer_tx2]);

        dbio.put_block(&block, [3; 32]).unwrap();

        let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
        let last_block = dbio.get_block(last_id).unwrap().unwrap();

        let prev_hash = last_block.header.hash;
        let transfer_tx =
            common::test_utils::create_transaction_native_token_transfer(from, 6, to, 1, &sign_key);
        tx_hash_res.push(transfer_tx.hash().0);

        let block = produce_dummy_block(4, Some(prev_hash), vec![transfer_tx]);

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
