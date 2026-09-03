use common::{test_utils::produce_dummy_block, transaction::TxEvents};
use lee::{Account, AccountId, PublicKey};
use tempfile::tempdir;

use super::*;

const INITIAL_ACC1_BALANCE: u128 = 10_000_000_000_000;
const INITIAL_ACC2_BALANCE: u128 = 20_000_000_000_000;

fn genesis_block() -> Block {
    produce_dummy_block(1, None, vec![])
}

/// `settled_block` with the dummy producers' optional previous hash.
fn settled_block_opt(
    id: u64,
    prev_hash: Option<common::HashType>,
    transactions: Vec<common::transaction::LeeTransaction>,
    state: &lee::V03State,
) -> Block {
    settled_block(id, prev_hash.unwrap_or_default(), transactions, state)
}

/// A block whose forced fee transaction carries the summary its user
/// transactions actually settle to (see `chain_state::apply::derive_block_summary`).
fn settled_block(
    id: u64,
    prev_hash: common::HashType,
    mut transactions: Vec<common::transaction::LeeTransaction>,
    state: &lee::V03State,
) -> Block {
    use common::transaction::{LeeTransaction, clock_invocation, fee_invocation};
    let timestamp = id.saturating_mul(100);
    let summary = if id == lee::GENESIS_BLOCK_ID {
        // Genesis transactions are fee-exempt
        fee_core::BlockFeeSummary::default()
    } else {
        chain_state::apply::derive_block_summary(state, &transactions, id, timestamp)
            .expect("test transactions settle")
    };
    let producer = lee::AccountId::from(&lee::PublicKey::new_from_private_key(
        &common::test_utils::sequencer_sign_key_for_testing(),
    ));
    transactions.push(LeeTransaction::Public(fee_invocation(summary, producer)));
    transactions.push(LeeTransaction::Public(clock_invocation(timestamp)));
    common::block::HashableBlockData {
        block_id: id,
        prev_block_hash: prev_hash,
        timestamp,
        transactions,
    }
    .into_pending_block(&common::test_utils::sequencer_sign_key_for_testing())
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
    let mut public_accounts = [
        (acc1(), INITIAL_ACC1_BALANCE),
        (acc2(), INITIAL_ACC2_BALANCE),
    ]
    .into_iter()
    .map(|(id, balance)| {
        (
            id,
            Account {
                program_owner: programs::authenticated_transfer().id().into(),
                balance,
                ..Account::default()
            },
        )
    })
    .collect::<Vec<_>>();

    // push clock system accounts
    for clock_id in system_accounts::clock_account_ids() {
        public_accounts.push((clock_id, system_accounts::clock_account()));
    }

    // push fee system accounts
    public_accounts.push((
        system_accounts::fee_state_account_id(),
        system_accounts::fee_state_account(),
    ));
    for fee_id in [
        system_accounts::fee_escrow_account_id(),
        system_accounts::fee_inbox_account_id(),
    ] {
        public_accounts.push((fee_id, system_accounts::fee_account()));
    }

    // simulate the producer's stake so charged blocks
    // can credit its reward account
    public_accounts.push(common::test_utils::claimed_producer_seed());

    lee::V03State::new()
        .with_public_accounts(public_accounts)
        .with_programs([
            programs::authenticated_transfer(),
            programs::clock(),
            programs::fee(),
        ])
}

#[test]
fn start_db() {
    let initial_state = initial_state();
    let temp_dir = tempdir().unwrap();
    let temdir_path = temp_dir.path();

    let dbio = RocksDBIO::open_or_create(temdir_path, &initial_state).unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap();
    let first_id = dbio.get_meta_first_block_id_in_db().unwrap();
    let is_first_set = dbio.get_meta_is_first_block_set().unwrap();
    let last_observed_l1_header = dbio.get_meta_last_observed_l1_lib_header_in_db().unwrap();
    let last_block = dbio.get_block(1).unwrap();
    let breakpoint = dbio.get_breakpoint(0).unwrap();
    let final_state = dbio.final_state().unwrap();

    assert_eq!(last_id, None);
    assert_eq!(first_id, None);
    assert_eq!(last_observed_l1_header, None);
    assert!(!is_first_set);
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
    let initial_state = initial_state();
    let temp_dir = tempdir().unwrap();
    let temdir_path = temp_dir.path();

    let dbio = RocksDBIO::open_or_create(temdir_path, &initial_state).unwrap();

    let genesis_block = genesis_block();
    dbio.put_block(&genesis_block, [0; 32], 0, &initial_state, &[])
        .unwrap();
    let mut build_state = initial_state.clone();
    chain_state::apply::apply_block_to_state(&genesis_block, &mut build_state)
        .expect("genesis applies");

    let prev_hash = genesis_block.header.hash;
    let from = acc1();
    let to = acc2();
    let sign_key = acc1_sign_key();

    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 0, to, 1, &sign_key);
    let block = settled_block(2, prev_hash, vec![transfer_tx], &build_state);
    chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("block applies");

    dbio.put_block(&block, [1; 32], 0, &initial_state, &[])
        .unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let first_id = dbio.get_meta_first_block_id_in_db().unwrap();
    let last_observed_l1_header = dbio
        .get_meta_last_observed_l1_lib_header_in_db()
        .unwrap()
        .unwrap();
    let is_first_set = dbio.get_meta_is_first_block_set().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();
    let breakpoint = dbio.get_breakpoint(0).unwrap();
    let final_state = dbio.final_state().unwrap();

    assert_eq!(last_id, 2);
    assert_eq!(first_id, Some(1));
    assert_eq!(last_observed_l1_header, [1; 32]);
    assert!(is_first_set);
    assert_eq!(last_block.header.hash, block.header.hash);
    // The recipient gains exactly the transferred amount; the sender also
    // pays a real fee on top of it.
    assert_eq!(
        final_state.get_account_by_id(acc2()).balance
            - breakpoint.get_account_by_id(acc2()).balance,
        1
    );
    assert!(
        breakpoint.get_account_by_id(acc1()).balance
            - final_state.get_account_by_id(acc1()).balance
            > 1
    );
}

#[test]
fn put_block_records_tip_inscription_slot() {
    let initial_state = initial_state();
    let temp_dir = tempdir().unwrap();
    let dbio = RocksDBIO::open_or_create(temp_dir.path(), &initial_state).unwrap();

    assert_eq!(dbio.get_meta_tip_slot_in_db().unwrap(), None);

    let genesis_block = genesis_block();
    dbio.put_block(&genesis_block, [0; 32], 1_000, &initial_state, &[])
        .unwrap();
    assert_eq!(dbio.get_meta_tip_slot_in_db().unwrap(), Some(1_000));

    let block = produce_dummy_block(2, Some(genesis_block.header.hash), vec![]);
    dbio.put_block(&block, [1; 32], 1_005, &initial_state, &[])
        .unwrap();
    assert_eq!(dbio.get_meta_tip_slot_in_db().unwrap(), Some(1_005));

    // Re-inserting a block at/below the tip must not move the tip slot.
    dbio.put_block(&genesis_block, [0; 32], 1_010, &initial_state, &[])
        .unwrap();
    assert_eq!(dbio.get_meta_tip_slot_in_db().unwrap(), Some(1_005));
}

#[test]
fn put_block_stores_breakpoint_in_same_batch() {
    let initial_state = initial_state();
    let temp_dir = tempdir().unwrap();
    let dbio = RocksDBIO::open_or_create(temp_dir.path(), &initial_state).unwrap();

    let from = acc1();
    let to = acc2();
    let sign_key = acc1_sign_key();

    // Chain blocks 1..=BREAKPOINT_INTERVAL. The snapshot is scheduled internally
    // by put_block at the boundary block; every call passes the same recognizable
    // marker state (the initial one), proving it's stored verbatim rather than
    // recomputed.
    let mut build_state = initial_state.clone();
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
        let block = settled_block_opt(i.into(), prev_hash, vec![transfer_tx], &build_state);
        chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("builds");

        dbio.put_block(&block, [i; 32], 0, &initial_state, &[])
            .unwrap();
    }

    let bp1 = dbio.get_breakpoint(1).unwrap();
    assert_eq!(bp1.get_account_by_id(acc1()).balance, INITIAL_ACC1_BALANCE);
    assert_eq!(bp1.get_account_by_id(acc2()).balance, INITIAL_ACC2_BALANCE);
    // Only the boundary block schedules a write: breakpoint 0 must be the only other one.
    assert_eq!(
        dbio.get_breakpoint(0)
            .unwrap()
            .get_account_by_id(acc1())
            .balance,
        INITIAL_ACC1_BALANCE
    );
}

#[test]
fn state_replay_falls_back_over_missing_breakpoints() {
    let initial_state = initial_state();
    let temp_dir = tempdir().unwrap();
    let dbio = RocksDBIO::open_or_create(temp_dir.path(), &initial_state).unwrap();

    let from = acc1();
    let to = acc2();
    let sign_key = acc1_sign_key();

    let mut build_state = initial_state.clone();
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
        let block = settled_block_opt(i, prev_hash, vec![transfer_tx], &build_state);
        let events =
            chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("builds");
        dbio.put_block(&block, [0; 32], 0, &initial_state, &events)
            .unwrap();
    }

    // Simulate a store whose boundary snapshot was lost (#605).
    dbio.delete_breakpoint(1).unwrap();
    assert!(dbio.get_breakpoint_opt(1).unwrap().is_none());
    let final_state = dbio.final_state().unwrap();
    // The recipient gains exactly one unit per block; the sender additionally
    // pays a real fee per charged transfer (none in the genesis block, whose
    // transactions are exempt).
    assert_eq!(
        final_state.get_account_by_id(acc2()).balance - INITIAL_ACC2_BALANCE,
        u128::from(BREAKPOINT_INTERVAL) + 1
    );
    assert!(
        INITIAL_ACC1_BALANCE - final_state.get_account_by_id(acc1()).balance
            > u128::from(BREAKPOINT_INTERVAL) + 1
    );
}

#[test]
fn simple_maps() {
    let initial_state = initial_state();
    let temp_dir = tempdir().unwrap();
    let temdir_path = temp_dir.path();

    let dbio = RocksDBIO::open_or_create(temdir_path, &initial_state).unwrap();

    let from = acc1();
    let to = acc2();
    let sign_key = acc1_sign_key();

    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 0, to, 1, &sign_key);
    let block = produce_dummy_block(1, None, vec![transfer_tx]);
    let mut build_state = initial_state.clone();
    chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("genesis applies");

    let control_hash1 = block.header.hash;

    dbio.put_block(&block, [1; 32], 0, &initial_state, &[])
        .unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 1, to, 1, &sign_key);
    let block = settled_block(2, prev_hash, vec![transfer_tx], &build_state);
    chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("block applies");

    let control_hash2 = block.header.hash;

    dbio.put_block(&block, [2; 32], 0, &initial_state, &[])
        .unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 2, to, 1, &sign_key);

    let control_tx_hash1 = transfer_tx.hash();

    let block = settled_block(3, prev_hash, vec![transfer_tx], &build_state);
    let events =
        chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("block applies");
    dbio.put_block(&block, [3; 32], 0, &initial_state, &events)
        .unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 3, to, 1, &sign_key);

    let control_tx_hash2 = transfer_tx.hash();

    let block = settled_block(4, prev_hash, vec![transfer_tx], &build_state);
    let events =
        chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("block applies");
    dbio.put_block(&block, [4; 32], 0, &initial_state, &events)
        .unwrap();

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
    let initial_state = initial_state();
    let temp_dir = tempdir().unwrap();
    let temdir_path = temp_dir.path();

    let mut block_res = vec![];

    let dbio = RocksDBIO::open_or_create(temdir_path, &initial_state).unwrap();

    let from = acc1();
    let to = acc2();
    let sign_key = acc1_sign_key();

    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 0, to, 1, &sign_key);
    let block = produce_dummy_block(1, None, vec![transfer_tx]);
    let mut build_state = initial_state.clone();
    chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("genesis applies");

    block_res.push(block.clone());
    dbio.put_block(&block, [1; 32], 0, &initial_state, &[])
        .unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 1, to, 1, &sign_key);
    let block = settled_block(2, prev_hash, vec![transfer_tx], &build_state);
    chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("block applies");

    block_res.push(block.clone());
    dbio.put_block(&block, [2; 32], 0, &initial_state, &[])
        .unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 2, to, 1, &sign_key);

    let block = settled_block(3, prev_hash, vec![transfer_tx], &build_state);
    chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("block applies");
    block_res.push(block.clone());
    dbio.put_block(&block, [3; 32], 0, &initial_state, &[])
        .unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 3, to, 1, &sign_key);

    let block = settled_block(4, prev_hash, vec![transfer_tx], &build_state);
    chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("block applies");
    block_res.push(block.clone());
    dbio.put_block(&block, [4; 32], 0, &initial_state, &[])
        .unwrap();

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
    let initial_state = initial_state();
    let temp_dir = tempdir().unwrap();
    let temdir_path = temp_dir.path();

    let dbio = RocksDBIO::open_or_create(temdir_path, &initial_state).unwrap();

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
    let mut build_state = initial_state.clone();
    chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("genesis applies");

    dbio.put_block(&block, [1; 32], 0, &initial_state, &[])
        .unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx1 =
        common::test_utils::create_transaction_native_token_transfer(from, 2, to, 1, &sign_key);
    let transfer_tx2 =
        common::test_utils::create_transaction_native_token_transfer(from, 3, to, 1, &sign_key);
    tx_hash_res.push(transfer_tx1.hash().0);
    tx_hash_res.push(transfer_tx2.hash().0);

    let block = settled_block(2, prev_hash, vec![transfer_tx1, transfer_tx2], &build_state);
    chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("block applies");

    dbio.put_block(&block, [2; 32], 0, &initial_state, &[])
        .unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx1 =
        common::test_utils::create_transaction_native_token_transfer(from, 4, to, 1, &sign_key);
    let transfer_tx2 =
        common::test_utils::create_transaction_native_token_transfer(from, 5, to, 1, &sign_key);
    tx_hash_res.push(transfer_tx1.hash().0);
    tx_hash_res.push(transfer_tx2.hash().0);

    let block = settled_block(3, prev_hash, vec![transfer_tx1, transfer_tx2], &build_state);
    chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("block applies");

    dbio.put_block(&block, [3; 32], 0, &initial_state, &[])
        .unwrap();

    let last_id = dbio.get_meta_last_block_id_in_db().unwrap().unwrap();
    let last_block = dbio.get_block(last_id).unwrap().unwrap();

    let prev_hash = last_block.header.hash;
    let transfer_tx =
        common::test_utils::create_transaction_native_token_transfer(from, 6, to, 1, &sign_key);
    tx_hash_res.push(transfer_tx.hash().0);

    let block = settled_block(4, prev_hash, vec![transfer_tx], &build_state);
    chain_state::apply::apply_block_to_state(&block, &mut build_state).expect("block applies");

    dbio.put_block(&block, [4; 32], 0, &initial_state, &[])
        .unwrap();

    let acc1_tx = dbio.get_acc_transactions(*acc1().value(), 0, 7).unwrap();
    let acc1_tx_hashes: Vec<[u8; 32]> = acc1_tx.into_iter().map(|tx| tx.hash().0).collect();

    assert_eq!(acc1_tx_hashes, tx_hash_res);

    let acc1_tx_limited = dbio.get_acc_transactions(*acc1().value(), 1, 4).unwrap();
    let acc1_tx_limited_hashes: Vec<[u8; 32]> =
        acc1_tx_limited.into_iter().map(|tx| tx.hash().0).collect();

    assert_eq!(acc1_tx_limited_hashes.as_slice(), &tx_hash_res[1..5]);
}

#[test]
fn reopen_preserves_seeded_breakpoint() {
    let initial_state = initial_state();
    let temp_dir = tempdir().unwrap();
    {
        let dbio = RocksDBIO::open_or_create(temp_dir.path(), &initial_state).unwrap();
        assert!(dbio.get_breakpoint_opt(0).unwrap().is_some());
    } // drop releases the RocksDB lock
    let dbio = RocksDBIO::open_or_create(temp_dir.path(), &initial_state).unwrap();
    assert!(dbio.get_breakpoint_opt(0).unwrap().is_some());
}

fn tx_events_fixture(tx_index: u32, tx_hash: [u8; 32]) -> TxEvents {
    TxEvents {
        tx_index,
        tx_hash: tx_hash.into(),
        events: vec![
            lee_core::program::TransactionEvent {
                program_id: [7; 8],
                event: lee_core::program::ProgramEvent {
                    selector: [1; 8],
                    data: vec![1, 2, 3],
                },
            },
            lee_core::program::TransactionEvent {
                program_id: [9; 8],
                event: lee_core::program::ProgramEvent {
                    selector: [2; 8],
                    data: vec![],
                },
            },
        ],
    }
}

#[test]
fn put_block_stores_events_in_same_batch() {
    let initial_state = initial_state();
    let temp_dir = tempdir().unwrap();
    let dbio = RocksDBIO::open_or_create(temp_dir.path(), &initial_state).unwrap();

    let block = genesis_block();
    let events = vec![
        tx_events_fixture(0, [11; 32]),
        tx_events_fixture(3, [12; 32]),
    ];

    dbio.put_block(&block, [0; 32], 0, &initial_state, &events)
        .unwrap();

    // One put_block call makes both the block and its events readable.
    assert!(dbio.get_block(1).unwrap().is_some());
    assert_eq!(dbio.get_block_events(1).unwrap(), Some(events));
}

#[test]
fn block_without_events_writes_no_row() {
    let initial_state = initial_state();
    let temp_dir = tempdir().unwrap();
    let dbio = RocksDBIO::open_or_create(temp_dir.path(), &initial_state).unwrap();

    dbio.put_block(&genesis_block(), [0; 32], 0, &initial_state, &[])
        .unwrap();

    assert!(dbio.get_block(1).unwrap().is_some());
    assert_eq!(dbio.get_block_events(1).unwrap(), None);
}

#[test]
fn get_block_events_is_none_for_unknown_block() {
    let initial_state = initial_state();
    let temp_dir = tempdir().unwrap();
    let dbio = RocksDBIO::open_or_create(temp_dir.path(), &initial_state).unwrap();

    assert_eq!(dbio.get_block_events(999).unwrap(), None);
}

#[test]
fn get_block_events_range_skips_blocks_without_events() {
    let initial_state = initial_state();
    let temp_dir = tempdir().unwrap();
    let dbio = RocksDBIO::open_or_create(temp_dir.path(), &initial_state).unwrap();

    let mut prev_hash = None;
    let mut expected = vec![];
    for block_id in 1..=4_u64 {
        let block = produce_dummy_block(block_id, prev_hash, vec![]);
        prev_hash = Some(block.header.hash);

        // Only odd blocks emit.
        let events = if block_id.is_multiple_of(2) {
            vec![]
        } else {
            vec![tx_events_fixture(0, [u8::try_from(block_id).unwrap(); 32])]
        };
        if !events.is_empty() {
            expected.push((block_id, events.clone()));
        }
        dbio.put_block(&block, [0; 32], 0, &initial_state, &events)
            .unwrap();
    }

    assert_eq!(dbio.get_block_events_range(1, 4).unwrap(), expected);
    assert_eq!(
        dbio.get_block_events_range(2, 2).unwrap(),
        Vec::<(u64, Vec<TxEvents>)>::new()
    );
    assert_eq!(dbio.get_block_events_range(3, 3).unwrap(), expected[1..]);
}
