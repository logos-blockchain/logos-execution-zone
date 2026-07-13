use common::test_utils::produce_dummy_block;
use lee::{Account, AccountId};
use tempfile::tempdir;

use super::*;

fn marker_id() -> AccountId {
    AccountId::new([1; 32])
}

/// A state distinguishable by the marker account's balance, so tests can tell
/// which snapshot a write persisted.
///
/// TODO: is this a bit too much of a hot-fix for test snapshot?
fn state_with_balance(balance: u128) -> V03State {
    V03State::new().with_public_accounts([(
        marker_id(),
        Account {
            balance,
            ..Account::default()
        },
    )])
}

fn dbio_with_genesis(path: &Path) -> (RocksDBIO, Block) {
    let genesis = produce_dummy_block(1, None, vec![]);
    let dbio = RocksDBIO::create(path, &genesis, &state_with_balance(100)).unwrap();
    (dbio, genesis)
}

fn stored_balance(dbio: &RocksDBIO) -> u128 {
    dbio.get_lee_state()
        .unwrap()
        .get_account_by_id(marker_id())
        .balance
}

#[test]
fn store_followed_block_persists_new_block_and_state() {
    let temp_dir = tempdir().unwrap();
    let (dbio, genesis) = dbio_with_genesis(temp_dir.path());

    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.store_followed_block(&block2, &state_with_balance(200), false)
        .unwrap();

    let stored = dbio.get_block(2).unwrap().expect("block 2 is stored");
    assert_eq!(stored.header.hash, block2.header.hash);
    assert!(matches!(stored.bedrock_status, BedrockStatus::Pending));
    assert_eq!(dbio.latest_block_meta().unwrap().id, 2);
    assert_eq!(stored_balance(&dbio), 200);
}

#[test]
fn store_followed_block_finalized_marks_block() {
    let temp_dir = tempdir().unwrap();
    let (dbio, genesis) = dbio_with_genesis(temp_dir.path());

    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.store_followed_block(&block2, &state_with_balance(200), true)
        .unwrap();

    let stored = dbio.get_block(2).unwrap().expect("block 2 is stored");
    assert!(matches!(stored.bedrock_status, BedrockStatus::Finalized));
}

#[test]
fn store_followed_block_redelivery_is_a_noop_and_keeps_finalized() {
    let temp_dir = tempdir().unwrap();
    let (dbio, genesis) = dbio_with_genesis(temp_dir.path());

    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.store_followed_block(&block2, &state_with_balance(200), true)
        .unwrap();
    dbio.store_followed_block(&block2, &state_with_balance(300), false)
        .unwrap();

    let stored = dbio.get_block(2).unwrap().expect("block 2 is stored");
    assert!(
        matches!(stored.bedrock_status, BedrockStatus::Finalized),
        "re-delivery must not demote a finalized block"
    );
    assert_eq!(
        stored_balance(&dbio),
        200,
        "re-delivery must not overwrite the persisted state"
    );
}

#[test]
fn store_followed_block_overwrites_competing_block_at_same_id() {
    let temp_dir = tempdir().unwrap();
    let (dbio, genesis) = dbio_with_genesis(temp_dir.path());

    let block2a = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.store_followed_block(&block2a, &state_with_balance(200), false)
        .unwrap();

    // A reorg replaces block 2: the competing block wins the slot.
    let block2b = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
    dbio.store_followed_block(&block2b, &state_with_balance(300), false)
        .unwrap();

    let stored = dbio.get_block(2).unwrap().expect("block 2 is stored");
    assert_eq!(stored.header.hash, block2b.header.hash);
    assert!(matches!(stored.bedrock_status, BedrockStatus::Pending));
    assert_eq!(stored_balance(&dbio), 300);
}
