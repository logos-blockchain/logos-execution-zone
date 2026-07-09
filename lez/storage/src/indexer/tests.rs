use common::test_utils::produce_dummy_block;
use lee::{Account, AccountId, PublicKey};
use tempfile::tempdir;

use super::*;

fn genesis_block() -> Block {
    produce_dummy_block(1, None, vec![])
}

fn acc1_sign_key() -> lee::PrivateKey {
    lee::PrivateKey::try_new([1; 32]).unwrap()
}

fn acc2_sign_key() -> lee::PrivateKey {
    lee::PrivateKey::try_new([2; 32]).unwrap()
}

fn acc1() -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(&acc1_sign_key()))
}

fn acc2() -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(&acc2_sign_key()))
}

fn initial_state() -> lee::V03State {
    let mut public_accounts = [(acc1(), 10000), (acc2(), 20000)]
        .into_iter()
        .map(|(id, balance)| {
            (
                id,
                Account {
                    program_owner: programs::authenticated_transfer().id(),
                    balance,
                    ..Account::default()
                },
            )
        })
        .collect::<Vec<_>>();
    for clock_id in system_accounts::clock_account_ids() {
        public_accounts.push((clock_id, system_accounts::clock_account()));
    }

    lee::V03State::new()
        .with_public_accounts(public_accounts)
        .with_programs([programs::authenticated_transfer(), programs::clock()])
}

#[test]
fn start_db() {
    let temp_dir = tempdir().unwrap();
    let temdir_path = temp_dir.path();

    let dbio = RocksDBIO::open_or_create(temdir_path, &initial_state()).unwrap();

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

    let dbio = RocksDBIO::open_or_create(temdir_path, &initial_state()).unwrap();

    let genesis_block = genesis_block();
    dbio.put_block(&genesis_block, [0; 32], 0, None).unwrap();

    let prev_hash = genesis_block.header.hash;
    let from = acc1();
    let to = acc2();
    let sign_key = acc1_sign_key();

    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 0, to, 1, &sign_key);
    let block = produce_dummy_block(2, Some(prev_hash), vec![transfer_tx]);

    dbio.put_block(&block, [1; 32], 0, None).unwrap();

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
fn put_block_rejects_breakpoint_on_non_boundary_block() {
    let temp_dir = tempdir().unwrap();
    let temdir_path = temp_dir.path();

    let dbio = RocksDBIO::open_or_create(temdir_path, &initial_state()).unwrap();

    let block = produce_dummy_block(1, None, vec![]);

    assert!(
        dbio.put_block(&block, [0; 32], 0, Some(&initial_state()))
            .is_err()
    );
}

#[test]
fn put_block_records_tip_inscription_slot() {
    let temp_dir = tempdir().unwrap();
    let dbio = RocksDBIO::open_or_create(temp_dir.path(), &initial_state()).unwrap();

    assert_eq!(dbio.get_meta_tip_slot_in_db().unwrap(), None);

    let genesis_block = genesis_block();
    dbio.put_block(&genesis_block, [0; 32], 1_000, None)
        .unwrap();
    assert_eq!(dbio.get_meta_tip_slot_in_db().unwrap(), Some(1_000));

    let block = produce_dummy_block(2, Some(genesis_block.header.hash), vec![]);
    dbio.put_block(&block, [1; 32], 1_005, None).unwrap();
    assert_eq!(dbio.get_meta_tip_slot_in_db().unwrap(), Some(1_005));

    // Re-inserting a block at/below the tip must not move the tip slot.
    dbio.put_block(&genesis_block, [0; 32], 1_010, None)
        .unwrap();
    assert_eq!(dbio.get_meta_tip_slot_in_db().unwrap(), Some(1_005));
}

#[test]
fn put_block_stores_breakpoint_in_same_batch() {
    let temp_dir = tempdir().unwrap();
    let dbio = RocksDBIO::open_or_create(temp_dir.path(), &initial_state()).unwrap();

    let from = acc1();
    let to = acc2();
    let sign_key = acc1_sign_key();

    // Chain blocks 1..=BREAKPOINT_INTERVAL; only the boundary block carries a
    // snapshot. A recognizable marker state (the initial one) proves put_block
    // stores the caller's snapshot verbatim rather than recomputing it.
    for i in 1..=BREAKPOINT_INTERVAL {
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

        let marker = (i == BREAKPOINT_INTERVAL).then(initial_state);
        dbio.put_block(&block, [i; 32], 0, marker.as_ref()).unwrap();
    }

    assert_eq!(dbio.get_meta_last_breakpoint_id().unwrap(), Some(1));
    let bp1 = dbio.get_breakpoint(1).unwrap();
    assert_eq!(bp1.get_account_by_id(acc1()).balance, 10000);
    assert_eq!(bp1.get_account_by_id(acc2()).balance, 20000);
    // Non-boundary blocks passed None: breakpoint 0 must be the only other one.
    assert_eq!(
        dbio.get_breakpoint(0)
            .unwrap()
            .get_account_by_id(acc1())
            .balance,
        10000
    );
}

#[test]
fn state_replay_falls_back_over_missing_breakpoints() {
    let temp_dir = tempdir().unwrap();
    let dbio = RocksDBIO::open_or_create(temp_dir.path(), &initial_state()).unwrap();

    let from = acc1();
    let to = acc2();
    let sign_key = acc1_sign_key();

    for i in 1..=u64::from(BREAKPOINT_INTERVAL) + 1 {
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
        let block = produce_dummy_block(i, prev_hash, vec![transfer_tx]);
        dbio.put_block(&block, [0; 32], 0, None).unwrap();
    }

    assert!(dbio.get_breakpoint_opt(1).unwrap().is_none());
    let final_state = dbio.final_state().unwrap();
    assert_eq!(
        10000 - final_state.get_account_by_id(acc1()).balance,
        u128::from(BREAKPOINT_INTERVAL) + 1
    );
    assert_eq!(
        final_state.get_account_by_id(acc2()).balance - 20000,
        u128::from(BREAKPOINT_INTERVAL) + 1
    );
}

#[test]
fn simple_maps() {
    let temp_dir = tempdir().unwrap();
    let temdir_path = temp_dir.path();

    let dbio = RocksDBIO::open_or_create(temdir_path, &initial_state()).unwrap();

    let from = acc1();
    let to = acc2();
    let sign_key = acc1_sign_key();

    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 0, to, 1, &sign_key);
    let block = produce_dummy_block(1, None, vec![transfer_tx]);

    let control_hash1 = block.header.hash;

    dbio.put_block(&block, [1; 32], 0, None).unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 1, to, 1, &sign_key);
    let block = produce_dummy_block(2, Some(prev_hash), vec![transfer_tx]);

    let control_hash2 = block.header.hash;

    dbio.put_block(&block, [2; 32], 0, None).unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 2, to, 1, &sign_key);

    let control_tx_hash1 = transfer_tx.hash();

    let block = produce_dummy_block(3, Some(prev_hash), vec![transfer_tx]);
    dbio.put_block(&block, [3; 32], 0, None).unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 3, to, 1, &sign_key);

    let control_tx_hash2 = transfer_tx.hash();

    let block = produce_dummy_block(4, Some(prev_hash), vec![transfer_tx]);
    dbio.put_block(&block, [4; 32], 0, None).unwrap();

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

    let dbio = RocksDBIO::open_or_create(temdir_path, &initial_state()).unwrap();

    let from = acc1();
    let to = acc2();
    let sign_key = acc1_sign_key();

    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 0, to, 1, &sign_key);
    let block = produce_dummy_block(1, None, vec![transfer_tx]);

    block_res.push(block.clone());
    dbio.put_block(&block, [1; 32], 0, None).unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 1, to, 1, &sign_key);
    let block = produce_dummy_block(2, Some(prev_hash), vec![transfer_tx]);

    block_res.push(block.clone());
    dbio.put_block(&block, [2; 32], 0, None).unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 2, to, 1, &sign_key);

    let block = produce_dummy_block(3, Some(prev_hash), vec![transfer_tx]);
    block_res.push(block.clone());
    dbio.put_block(&block, [3; 32], 0, None).unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 3, to, 1, &sign_key);

    let block = produce_dummy_block(4, Some(prev_hash), vec![transfer_tx]);
    block_res.push(block.clone());
    dbio.put_block(&block, [4; 32], 0, None).unwrap();

    let block_hashes_mem: Vec<[u8; 32]> =
        block_res.into_iter().map(|bl| bl.header.hash.0).collect();

    // Get blocks before ID 5 (i.e., starting from 4 going backwards), limit 4
    // This should return blocks 4, 3, 2, 1 in descending order
    let mut batch_res = dbio.get_block_batch(Some(5), 4).unwrap();
    batch_res.reverse(); // Reverse to match ascending order for comparison

    let block_hashes_db: Vec<[u8; 32]> = batch_res.into_iter().map(|bl| bl.header.hash.0).collect();

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

    let dbio = RocksDBIO::open_or_create(temdir_path, &initial_state()).unwrap();

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

    dbio.put_block(&block, [1; 32], 0, None).unwrap();

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

    dbio.put_block(&block, [2; 32], 0, None).unwrap();

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

    dbio.put_block(&block, [3; 32], 0, None).unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 6, to, 1, &sign_key);
    tx_hash_res.push(transfer_tx.hash().0);

    let block = produce_dummy_block(4, Some(prev_hash), vec![transfer_tx]);

    dbio.put_block(&block, [4; 32], 0, None).unwrap();

    let acc1_tx = dbio.get_acc_transactions(*acc1().value(), 0, 7).unwrap();
    let acc1_tx_hashes: Vec<[u8; 32]> = acc1_tx.into_iter().map(|tx| tx.hash().0).collect();

    assert_eq!(acc1_tx_hashes, tx_hash_res);

    let acc1_tx_limited = dbio.get_acc_transactions(*acc1().value(), 1, 4).unwrap();
    let acc1_tx_limited_hashes: Vec<[u8; 32]> =
        acc1_tx_limited.into_iter().map(|tx| tx.hash().0).collect();

    assert_eq!(acc1_tx_limited_hashes.as_slice(), &tx_hash_res[1..5]);
}

#[test]
fn reopen_preserves_breakpoint_meta() {
    let temp_dir = tempdir().unwrap();
    {
        let dbio = RocksDBIO::open_or_create(temp_dir.path(), &initial_state()).unwrap();
        dbio.put_meta_last_breakpoint_id(5).unwrap();
    } // drop releases the RocksDB lock
    let dbio = RocksDBIO::open_or_create(temp_dir.path(), &initial_state()).unwrap();
    assert_eq!(dbio.get_meta_last_breakpoint_id().unwrap(), Some(5));
}
