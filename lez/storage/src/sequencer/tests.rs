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

fn deposit_record(seed: u8) -> PendingDepositEventRecord {
    PendingDepositEventRecord {
        deposit_op_id: HashType([seed; 32]),
        source_tx_hash: HashType([seed; 32]),
        amount: u64::from(seed),
        metadata: vec![seed],
    }
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
    assert_eq!(
        dbio.latest_block_meta().unwrap().expect("meta is set").id,
        2
    );
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
fn store_followed_blocks_batch_lands_meta_and_state_on_last_block() {
    let temp_dir = tempdir().unwrap();
    let (dbio, genesis) = dbio_with_genesis(temp_dir.path());

    // Block 2 is already stored (own production); one update then finalizes it
    // and adopts block 3.
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.store_followed_block(&block2, &state_with_balance(200), false)
        .unwrap();

    let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
    let head_tip = BlockMeta {
        id: 3,
        hash: block3.header.hash,
    };
    dbio.store_update(&StoreUpdate {
        blocks: &[(&block2, true), (&block3, false)],
        head_tip: Some(&head_tip),
        ..StoreUpdate::new(&state_with_balance(300))
    })
    .unwrap();

    let stored2 = dbio.get_block(2).unwrap().expect("block 2 is stored");
    assert!(matches!(stored2.bedrock_status, BedrockStatus::Finalized));
    let stored3 = dbio.get_block(3).unwrap().expect("block 3 is stored");
    assert!(matches!(stored3.bedrock_status, BedrockStatus::Pending));

    // Meta and state land together on the last block of the batch.
    let meta = dbio.latest_block_meta().unwrap().expect("meta is set");
    assert_eq!(meta.id, 3);
    assert_eq!(meta.hash, block3.header.hash);
    assert_eq!(stored_balance(&dbio), 300);
}

#[test]
fn final_snapshot_round_trips_and_is_absent_on_fresh_store() {
    let temp_dir = tempdir().unwrap();
    let (dbio, genesis) = dbio_with_genesis(temp_dir.path());

    // Fresh store: no finalization observed yet.
    assert!(dbio.get_final_snapshot().unwrap().is_none());

    // A follow update that finalizes block 2 lands the snapshot in the same batch.
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let final_meta = BlockMeta {
        id: 2,
        hash: block2.header.hash,
    };
    dbio.store_update(&StoreUpdate {
        blocks: &[(&block2, true)],
        head_tip: Some(&final_meta),
        final_snapshot: Some((&state_with_balance(200), &final_meta)),
        ..StoreUpdate::new(&state_with_balance(300))
    })
    .unwrap();

    let (final_state, meta) = dbio
        .get_final_snapshot()
        .unwrap()
        .expect("final snapshot is stored");
    assert_eq!(meta.id, 2);
    assert_eq!(meta.hash, block2.header.hash);
    assert_eq!(final_state.get_account_by_id(marker_id()).balance, 200);
    // The head state is stored independently of the final snapshot.
    assert_eq!(stored_balance(&dbio), 300);
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

    // The tip meta must follow the reorg winner, or a restart seeds the chain
    // from the orphaned block's hash.
    let meta = dbio.latest_block_meta().unwrap().expect("meta is set");
    assert_eq!(meta.id, 2);
    assert_eq!(meta.hash, block2b.header.hash);
}

#[test]
fn net_shortening_reorg_drops_stale_blocks() {
    let temp_dir = tempdir().unwrap();
    let (dbio, genesis) = dbio_with_genesis(temp_dir.path());

    let block2a = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.store_followed_block(&block2a, &state_with_balance(200), false)
        .unwrap();
    let block3 = produce_dummy_block(3, Some(block2a.header.hash), vec![]);
    dbio.store_followed_block(&block3, &state_with_balance(300), false)
        .unwrap();

    // A shorter competing chain wins: block 2 is replaced, block 3 gets no
    // replacement.
    let block2b = produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
    let head_tip = BlockMeta {
        id: 2,
        hash: block2b.header.hash,
    };
    dbio.store_update(&StoreUpdate {
        blocks: &[(&block2b, false)],
        head_tip: Some(&head_tip),
        ..StoreUpdate::new(&state_with_balance(400))
    })
    .unwrap();

    let stored2 = dbio.get_block(2).unwrap().expect("block 2 is stored");
    assert_eq!(stored2.header.hash, block2b.header.hash);
    assert!(
        dbio.get_block(3).unwrap().is_none(),
        "stale block above the new head must be deleted, or restart replay panics on its broken link"
    );
    let meta = dbio.latest_block_meta().unwrap().expect("meta is set");
    assert_eq!(meta.id, 2);
    assert_eq!(meta.hash, block2b.header.hash);
    assert_eq!(stored_balance(&dbio), 400);
}

#[test]
fn shrink_only_reorg_rewinds_tip_meta() {
    let temp_dir = tempdir().unwrap();
    let (dbio, genesis) = dbio_with_genesis(temp_dir.path());

    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.store_followed_block(&block2, &state_with_balance(200), false)
        .unwrap();
    let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
    dbio.store_followed_block(&block3, &state_with_balance(300), false)
        .unwrap();

    // Orphan-only update: block 3 falls off the branch with no replacement.
    let head_tip = BlockMeta {
        id: 2,
        hash: block2.header.hash,
    };
    dbio.store_update(&StoreUpdate {
        head_tip: Some(&head_tip),
        ..StoreUpdate::new(&state_with_balance(200))
    })
    .unwrap();

    assert!(
        dbio.get_block(3).unwrap().is_none(),
        "the orphaned block must not survive the tip rewind"
    );
    let meta = dbio.latest_block_meta().unwrap().expect("meta is set");
    assert_eq!(meta.id, 2);
    assert_eq!(meta.hash, block2.header.hash);
    assert_eq!(stored_balance(&dbio), 200);
}

#[test]
fn checkpoint_lands_with_an_orphan_only_update() {
    let temp_dir = tempdir().unwrap();
    let (dbio, genesis) = dbio_with_genesis(temp_dir.path());

    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.store_followed_block(&block2, &state_with_balance(200), false)
        .unwrap();
    let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
    dbio.store_followed_block(&block3, &state_with_balance(300), false)
        .unwrap();

    // Orphan-only update: no payload to write, but the checkpoint covering it
    // must still land, or a restart resumes past the orphan.
    let head_tip = BlockMeta {
        id: 2,
        hash: block2.header.hash,
    };
    dbio.store_update(&StoreUpdate {
        checkpoint: Some(b"cp-orphan"),
        head_tip: Some(&head_tip),
        ..StoreUpdate::new(&state_with_balance(200))
    })
    .unwrap();

    assert_eq!(
        dbio.get_zone_sdk_checkpoint_bytes().unwrap().as_deref(),
        Some(b"cp-orphan".as_slice())
    );
    assert!(dbio.get_block(3).unwrap().is_none());
}

#[test]
fn checkpoint_only_update_does_not_rewrite_the_head_state() {
    let temp_dir = tempdir().unwrap();
    let (dbio, genesis) = dbio_with_genesis(temp_dir.path());

    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.store_followed_block(&block2, &state_with_balance(200), false)
        .unwrap();

    // An event carrying nothing but a checkpoint (the common case) must not
    // drag a full state serialization along with it — the caller's state is
    // ignored while the chain stands still.
    let head_tip = BlockMeta::from(&block2);
    dbio.store_update(&StoreUpdate {
        checkpoint: Some(b"cp-idle"),
        head_tip: Some(&head_tip),
        ..StoreUpdate::new(&state_with_balance(999))
    })
    .unwrap();

    assert_eq!(
        dbio.get_zone_sdk_checkpoint_bytes().unwrap().as_deref(),
        Some(b"cp-idle".as_slice())
    );
    assert_eq!(stored_balance(&dbio), 200);
}

#[test]
fn several_deposits_in_one_update_are_all_recorded() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    // The records live in one whole-vector cell: staged per event against a
    // fresh disk read, the second would clobber the first.
    let first = deposit_record(1);
    let second = deposit_record(2);
    let already_known = dbio.get_pending_deposit_events().unwrap();
    assert!(already_known.is_empty());

    let outcome = dbio
        .store_update(&StoreUpdate {
            new_deposit_events: &[first.clone(), second.clone()],
            ..StoreUpdate::new(&state_with_balance(100))
        })
        .unwrap();

    assert_eq!(outcome.accepted_deposits, 2);
    let stored = dbio.get_pending_deposit_events().unwrap();
    assert_eq!(stored.len(), 2);
    assert!(stored.contains(&first));
    assert!(stored.contains(&second));
}

#[test]
fn redelivered_deposit_is_not_accepted_twice() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    let record = deposit_record(1);
    dbio.store_update(&StoreUpdate {
        new_deposit_events: std::slice::from_ref(&record),
        ..StoreUpdate::new(&state_with_balance(100))
    })
    .unwrap();

    let outcome = dbio
        .store_update(&StoreUpdate {
            new_deposit_events: &[record],
            ..StoreUpdate::new(&state_with_balance(100))
        })
        .unwrap();

    assert_eq!(
        outcome.accepted_deposits, 0,
        "a re-delivered deposit is already owed, not newly accepted"
    );
    assert_eq!(dbio.get_pending_deposit_events().unwrap().len(), 1);
}

#[test]
fn finalized_deposit_records_are_removed_by_op_id() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    let first = deposit_record(1);
    let second = deposit_record(2);
    dbio.store_update(&StoreUpdate {
        new_deposit_events: &[first.clone(), second.clone()],
        ..StoreUpdate::new(&state_with_balance(100))
    })
    .unwrap();

    // Only the finalized op id is dropped; the other record stays.
    dbio.store_update(&StoreUpdate {
        remove_deposit_records: &[first.deposit_op_id],
        ..StoreUpdate::new(&state_with_balance(100))
    })
    .unwrap();

    let stored = dbio.get_pending_deposit_events().unwrap();
    assert_eq!(stored, vec![second]);
}

#[test]
fn repeated_withdrawal_key_in_one_update_folds_once_per_occurrence() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    let key = WithdrawalReconciliationKey {
        released_note_id: [3; 32],
    };

    // Two local intents for the same key in one update. A per-occurrence disk
    // read would miss the staged increment and record the pair as one.
    dbio.store_update(&StoreUpdate {
        new_withdraw_intents: &[key, key],
        ..StoreUpdate::new(&state_with_balance(100))
    })
    .unwrap();
    let recorded = dbio
        .get_opt::<UnseenWithdrawCountCell>(key)
        .unwrap()
        .map(|cell| cell.0);
    assert_eq!(recorded, Some(2));

    // Both L1 events arrive in one update; a per-occurrence disk read would
    // miss the staged decrement and consume only one.
    let outcome = dbio
        .store_update(&StoreUpdate {
            consumed_withdrawals: &[key, key],
            ..StoreUpdate::new(&state_with_balance(100))
        })
        .unwrap();

    assert!(outcome.unmatched_withdrawals.is_empty());
    // Both decrements landed; a per-occurrence disk read would leave `Some(1)`.
    // (The absolute value trails the intent count by one — `consume` still
    // treats a stored 0 as consumable — but that predates the batching and is
    // replicated as-is.)
    let remaining = dbio
        .get_opt::<UnseenWithdrawCountCell>(key)
        .unwrap()
        .map(|cell| cell.0);
    assert_eq!(remaining, Some(0));
}

#[test]
fn unmatched_withdrawal_is_reported_and_writes_nothing() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    let key = WithdrawalReconciliationKey {
        released_note_id: [4; 32],
    };
    let outcome = dbio
        .store_update(&StoreUpdate {
            consumed_withdrawals: &[key],
            ..StoreUpdate::new(&state_with_balance(100))
        })
        .unwrap();

    assert_eq!(outcome.unmatched_withdrawals.len(), 1);
    assert!(
        dbio.get_opt::<UnseenWithdrawCountCell>(key)
            .unwrap()
            .is_none(),
        "an unmatched withdraw must not leave a counter behind"
    );
}

#[test]
fn produced_block_persists_its_publish_checkpoint() {
    let temp_dir = tempdir().unwrap();
    let (dbio, genesis) = dbio_with_genesis(temp_dir.path());

    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.atomic_update(&block2, &[], &state_with_balance(200), Some(b"cp-produced"))
        .unwrap();

    // Storing the block without the checkpoint would let a restart restore a
    // pending set that no longer holds the inscription we just published.
    assert_eq!(
        dbio.get_zone_sdk_checkpoint_bytes().unwrap().as_deref(),
        Some(b"cp-produced".as_slice())
    );
    assert_eq!(
        dbio.get_block(2).unwrap().unwrap().header.hash,
        block2.header.hash
    );
}

#[test]
fn produced_block_below_disk_head_pins_meta_and_prunes() {
    let temp_dir = tempdir().unwrap();
    let (dbio, genesis) = dbio_with_genesis(temp_dir.path());

    let block2a = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.store_followed_block(&block2a, &state_with_balance(200), false)
        .unwrap();
    let block3 = produce_dummy_block(3, Some(block2a.header.hash), vec![]);
    dbio.store_followed_block(&block3, &state_with_balance(300), false)
        .unwrap();

    // Producing at height 2 while the disk head is still 3: the produce path
    // pins the tip meta to the produced block and drops the stale suffix in
    // the same write, mirroring the follow path.
    let block2b = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.atomic_update(&block2b, &[], &state_with_balance(400), None)
        .unwrap();

    let stored2 = dbio.get_block(2).unwrap().expect("block 2 is stored");
    assert_eq!(stored2.header.hash, block2b.header.hash);
    assert!(dbio.get_block(3).unwrap().is_none());
    let meta = dbio.latest_block_meta().unwrap().expect("meta is set");
    assert_eq!(meta.id, 2);
    assert_eq!(meta.hash, block2b.header.hash);
    assert_eq!(stored_balance(&dbio), 400);
}
