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
    let dbio = RocksDBIO::open_or_create(path).unwrap();
    // The same write any block takes: the first one into an empty store starts
    // its chain.
    dbio.atomic_update(&genesis, None, &[], &state_with_balance(100), None)
        .unwrap();
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

fn dispatch_record(seed: u8) -> PendingCrossZoneDispatchRecord {
    PendingCrossZoneDispatchRecord::recorded([seed; 32], vec![seed; 4])
}

/// The peer coordinates a dead letter carries, distinct per seed.
fn dispatch_origin(seed: u8) -> DispatchOrigin {
    DispatchOrigin {
        src_zone: [seed; 32],
        src_block_id: u64::from(seed),
        src_tx_index: u32::from(seed),
    }
}

/// A distinct message key per index, for filling the pending list.
fn key_from_index(index: usize) -> [u8; 32] {
    let mut key = [0_u8; 32];
    key[..8].copy_from_slice(&u64::try_from(index).expect("test index fits").to_le_bytes());
    key
}

/// `records` in message-key order, the order the store reports them in.
fn sorted_dispatches(
    mut records: Vec<PendingCrossZoneDispatchRecord>,
) -> Vec<PendingCrossZoneDispatchRecord> {
    records.sort_by_key(|record| record.message_key);
    records
}

fn stored_balance(dbio: &RocksDBIO) -> u128 {
    dbio.get_lee_state()
        .unwrap()
        .expect("the store holds a chain")
        .get_account_by_id(marker_id())
        .balance
}

/// The channel cursor has to outlive the process: a restart that cannot
/// recover it has nothing to chain the next publish onto.
#[test]
fn channel_cursor_survives_reopening_the_store() {
    let temp_dir = tempdir().unwrap();
    let (dbio, genesis) = dbio_with_genesis(temp_dir.path());

    assert_eq!(
        dbio.channel_cursor().unwrap(),
        None,
        "a store written without a cursor has none to report"
    );
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.atomic_update(&block2, Some([7; 32]), &[], &state_with_balance(200), None)
        .unwrap();
    drop(dbio);

    let reopened = RocksDBIO::open_or_create(temp_dir.path()).unwrap();
    assert_eq!(
        reopened.channel_cursor().unwrap(),
        Some([7; 32]),
        "the cursor must come back after a restart"
    );
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
fn peer_chain_tips_round_trip_and_are_kept_per_peer() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    let peer_a = [1_u8; 32];
    let peer_b = [2_u8; 32];
    assert_eq!(dbio.get_cross_zone_peer_tip(peer_a).unwrap(), None);

    let tip_a = PeerChainTip {
        block_id: 7,
        block_hash: HashType([9; 32]),
    };
    let tip_b = PeerChainTip {
        block_id: 3,
        block_hash: HashType([4; 32]),
    };
    // The floor shares this peer key with the tip. Asserting the tip alone
    // passes even when the two cells occupy one key space.
    dbio.put_cross_zone_peer_floor_bytes(peer_a, &11_u64.to_le_bytes())
        .unwrap();
    dbio.put_cross_zone_peer_tip(peer_a, tip_a).unwrap();
    dbio.put_cross_zone_peer_tip(peer_b, tip_b).unwrap();

    // One tip per peer: a shared key would let one peer's chain decide which
    // blocks another peer's watcher accepts.
    assert_eq!(dbio.get_cross_zone_peer_tip(peer_a).unwrap(), Some(tip_a));
    assert_eq!(dbio.get_cross_zone_peer_tip(peer_b).unwrap(), Some(tip_b));
    assert_eq!(
        dbio.get_cross_zone_peer_floor_bytes(peer_a).unwrap(),
        Some(11_u64.to_le_bytes().to_vec()),
        "the tip must not land in the floor's key space"
    );

    let advanced = PeerChainTip {
        block_id: 8,
        block_hash: HashType([10; 32]),
    };
    dbio.put_cross_zone_peer_tip(peer_a, advanced).unwrap();
    assert_eq!(
        dbio.get_cross_zone_peer_tip(peer_a).unwrap(),
        Some(advanced)
    );
    assert_eq!(dbio.get_cross_zone_peer_tip(peer_b).unwrap(), Some(tip_b));

    // Clearing the floor is how a watcher with no tip rebuilds one, so it has
    // to leave the tip alone: the two share the peer key and differ only in
    // their key base.
    dbio.delete_cross_zone_peer_floor(peer_a).unwrap();
    assert_eq!(dbio.get_cross_zone_peer_floor_bytes(peer_a).unwrap(), None);
    assert_eq!(
        dbio.get_cross_zone_peer_tip(peer_a).unwrap(),
        Some(advanced)
    );
    dbio.delete_cross_zone_peer_floor(peer_a)
        .expect("clearing a floor that is already gone is not an error");

    // On disk, not in memory: a watcher that re-anchored on restart would take
    // whatever block reached it first, which is the id the attack picks.
    drop(dbio);
    let reopened = RocksDBIO::open_or_create(temp_dir.path()).unwrap();
    assert_eq!(
        reopened.get_cross_zone_peer_tip(peer_a).unwrap(),
        Some(advanced)
    );
    assert_eq!(
        reopened.get_cross_zone_peer_tip(peer_b).unwrap(),
        Some(tip_b)
    );
}

#[test]
fn dispatch_records_round_trip_and_dedupe_by_message_key() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    let record = dispatch_record(1);
    assert_eq!(
        dbio.add_pending_cross_zone_dispatches(vec![record.clone()])
            .unwrap(),
        1
    );
    // The watcher re-reads a slot it stalled on, so the same delivery arrives
    // again; recording it twice would double-count its failed attempts.
    assert_eq!(
        dbio.add_pending_cross_zone_dispatches(vec![record.clone(), dispatch_record(2)])
            .unwrap(),
        1,
        "only the delivery not already held is newly recorded"
    );

    // Set equality, not order: no insertion order survives the store.
    assert_eq!(
        sorted_dispatches(dbio.get_pending_cross_zone_dispatches().unwrap()),
        sorted_dispatches(vec![record, dispatch_record(2)])
    );
    assert_eq!(dbio.get_pending_cross_zone_dispatch_count().unwrap(), 2);
}

#[test]
fn recording_past_the_cap_writes_nothing() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    // What fills this list is chosen by peer zones, so the bound is what stops a
    // peer deciding how large our store gets. Refusing the whole write leaves
    // the watcher's floor where it is, so the slot is read again later and
    // nothing is lost.
    let full: Vec<_> = (0..MAX_PENDING_CROSS_ZONE_DISPATCHES)
        .map(|seed| PendingCrossZoneDispatchRecord::recorded(key_from_index(seed), vec![0_u8; 4]))
        .collect();
    assert_eq!(
        dbio.add_pending_cross_zone_dispatches(full).unwrap(),
        MAX_PENDING_CROSS_ZONE_DISPATCHES
    );

    let over = PendingCrossZoneDispatchRecord::recorded(
        key_from_index(MAX_PENDING_CROSS_ZONE_DISPATCHES),
        vec![0_u8; 4],
    );
    assert!(
        dbio.add_pending_cross_zone_dispatches(vec![over]).is_err(),
        "recording past the cap must fail so the caller holds its floor"
    );
    assert_eq!(
        dbio.get_pending_cross_zone_dispatches().unwrap().len(),
        MAX_PENDING_CROSS_ZONE_DISPATCHES,
        "a refused write must leave the records untouched"
    );
    assert_eq!(
        dbio.get_pending_cross_zone_dispatch_count().unwrap(),
        u64::try_from(MAX_PENDING_CROSS_ZONE_DISPATCHES).unwrap(),
        "and the count cell with them"
    );

    // Re-offering only what is already held is not growth, so it still succeeds.
    assert_eq!(
        dbio.add_pending_cross_zone_dispatches(vec![PendingCrossZoneDispatchRecord::recorded(
            key_from_index(0),
            vec![0_u8; 4]
        )])
        .unwrap(),
        0
    );
}

#[test]
fn dispatch_records_survive_a_reopen() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    let first = dispatch_record(1);
    let second = dispatch_record(2);
    dbio.add_pending_cross_zone_dispatches(vec![first.clone(), second.clone()])
        .unwrap();

    // On disk, not in memory: the records are what stand between the watcher's
    // durable read floor and a lost delivery across a restart.
    drop(dbio);
    let reopened = RocksDBIO::open_or_create(temp_dir.path()).unwrap();
    assert_eq!(
        sorted_dispatches(reopened.get_pending_cross_zone_dispatches().unwrap()),
        sorted_dispatches(vec![first, second])
    );
    assert_eq!(reopened.get_pending_cross_zone_dispatch_count().unwrap(), 2);
}

#[test]
fn a_legacy_dispatch_blob_is_migrated_into_per_message_entries_on_open() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    // A store written before the per-message layout: the whole set as one borsh
    // blob under a single fixed key.
    let records = vec![dispatch_record(1), dispatch_record(2), dispatch_record(3)];
    let legacy_key = borsh::to_vec(&DB_META_PENDING_CROSS_ZONE_DISPATCHES_KEY).unwrap();
    dbio.db
        .put_cf(
            &dbio.meta_column(),
            &legacy_key,
            borsh::to_vec(&records).unwrap(),
        )
        .unwrap();
    drop(dbio);

    let migrated = RocksDBIO::open_or_create(temp_dir.path()).unwrap();
    assert_eq!(
        sorted_dispatches(migrated.get_pending_cross_zone_dispatches().unwrap()),
        sorted_dispatches(records.clone()),
        "every record must come through the migration unchanged"
    );
    for record in &records {
        assert_eq!(
            migrated
                .get_opt::<PendingCrossZoneDispatchCellOwned>(record.message_key)
                .unwrap()
                .map(|cell| cell.0),
            Some(record.clone()),
            "each record must be readable under its own message key"
        );
    }
    assert_eq!(migrated.get_pending_cross_zone_dispatch_count().unwrap(), 3);
    assert!(
        migrated
            .db
            .get_cf(&migrated.meta_column(), &legacy_key)
            .unwrap()
            .is_none(),
        "the blob must not survive the migration"
    );

    // An empty blob is deleted without touching the migrated entries or count.
    let empty: Vec<PendingCrossZoneDispatchRecord> = Vec::new();
    migrated
        .db
        .put_cf(
            &migrated.meta_column(),
            &legacy_key,
            borsh::to_vec(&empty).unwrap(),
        )
        .unwrap();
    drop(migrated);

    let cleaned = RocksDBIO::open_or_create(temp_dir.path()).unwrap();
    assert!(
        cleaned
            .db
            .get_cf(&cleaned.meta_column(), &legacy_key)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        cleaned.get_pending_cross_zone_dispatches().unwrap().len(),
        3
    );
    assert_eq!(cleaned.get_pending_cross_zone_dispatch_count().unwrap(), 3);
}

/// A blob restored over live per-message entries folds additively into the
/// count.
#[test]
fn a_legacy_blob_over_live_entries_folds_additively() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    dbio.add_pending_cross_zone_dispatches(vec![dispatch_record(1), dispatch_record(2)])
        .unwrap();

    // The blob shares record 2 with the live entries and brings record 3.
    let blob = vec![dispatch_record(2), dispatch_record(3)];
    let legacy_key = borsh::to_vec(&DB_META_PENDING_CROSS_ZONE_DISPATCHES_KEY).unwrap();
    dbio.db
        .put_cf(
            &dbio.meta_column(),
            &legacy_key,
            borsh::to_vec(&blob).unwrap(),
        )
        .unwrap();
    drop(dbio);

    let merged = RocksDBIO::open_or_create(temp_dir.path()).unwrap();
    assert_eq!(
        sorted_dispatches(merged.get_pending_cross_zone_dispatches().unwrap()),
        sorted_dispatches(vec![
            dispatch_record(1),
            dispatch_record(2),
            dispatch_record(3)
        ]),
        "the migration must keep the union of blob and live entries"
    );
    assert_eq!(
        merged.get_pending_cross_zone_dispatch_count().unwrap(),
        3,
        "the count must be the union's size, not the blob's length"
    );
}

#[test]
fn the_dispatch_count_cell_tracks_the_stored_entries() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    let count_and_entries_agree = |expected: u64| {
        assert_eq!(
            dbio.get_pending_cross_zone_dispatch_count().unwrap(),
            expected
        );
        assert_eq!(
            u64::try_from(dbio.get_pending_cross_zone_dispatches().unwrap().len()).unwrap(),
            expected,
            "the count cell and the scanned entries must never disagree"
        );
    };

    dbio.add_pending_cross_zone_dispatches(vec![
        dispatch_record(1),
        dispatch_record(2),
        dispatch_record(3),
    ])
    .unwrap();
    count_and_entries_agree(3);

    // A counted retry keeps the record, so the count stands still.
    dbio.record_dispatch_failure([1; 32], 2, dispatch_origin(1))
        .unwrap();
    count_and_entries_agree(3);

    // A retirement into the dead letter takes its record out.
    dbio.record_dispatch_failure([1; 32], 2, dispatch_origin(1))
        .unwrap();
    count_and_entries_agree(2);

    // As does a standalone settled drop, even repeated on a key already gone.
    dbio.drop_settled_cross_zone_dispatches(&[[2; 32], [2; 32]])
        .unwrap();
    count_and_entries_agree(1);

    // And the settlement path inside a store update.
    dbio.store_update(&StoreUpdate {
        remove_dispatch_records: &[[3; 32]],
        ..StoreUpdate::new(&state_with_balance(100))
    })
    .unwrap();
    count_and_entries_agree(0);
}

#[test]
fn settled_dispatch_records_are_dropped_outside_an_update() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    // The watcher re-reads a slot it already consumed and re-records a delivery
    // that settled long ago. Its key will never appear in a future block, so the
    // store-update path cannot reach it and this is the only thing that does.
    let first = dispatch_record(1);
    let second = dispatch_record(2);
    dbio.add_pending_cross_zone_dispatches(vec![first.clone(), second.clone()])
        .unwrap();

    assert_eq!(
        dbio.drop_settled_cross_zone_dispatches(&[first.message_key])
            .unwrap(),
        1
    );
    assert_eq!(
        dbio.get_pending_cross_zone_dispatches().unwrap(),
        vec![second]
    );

    // Dropping one that is already gone is a no-op, not an error.
    assert_eq!(
        dbio.drop_settled_cross_zone_dispatches(&[first.message_key])
            .unwrap(),
        0
    );
}

#[test]
fn finalized_dispatch_records_are_removed_by_message_key() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    let first = dispatch_record(1);
    let second = dispatch_record(2);
    dbio.add_pending_cross_zone_dispatches(vec![first.clone(), second.clone()])
        .unwrap();

    // Only the finalized delivery's key is dropped. Two deliveries can sit in
    // the same block, so a record must go by its own identity rather than by
    // anything about the height its delivery landed at.
    dbio.store_update(&StoreUpdate {
        remove_dispatch_records: &[first.message_key],
        ..StoreUpdate::new(&state_with_balance(100))
    })
    .unwrap();

    assert_eq!(
        dbio.get_pending_cross_zone_dispatches().unwrap(),
        vec![second]
    );
}

#[test]
fn record_dispatch_failure_retires_the_record_at_the_limit() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    let record = dispatch_record(1);
    let key = record.message_key;
    let survivor = dispatch_record(2);
    dbio.add_pending_cross_zone_dispatches(vec![record, survivor.clone()])
        .unwrap();

    assert_eq!(
        dbio.record_dispatch_failure(key, 3, dispatch_origin(1))
            .unwrap(),
        DispatchFailure::Retried { failed_attempts: 1 },
        "a failure short of the limit is counted, not given up on"
    );
    assert_eq!(
        dbio.get_pending_cross_zone_dispatches().unwrap()[0].failed_attempts,
        1
    );
    assert_eq!(
        dbio.record_dispatch_failure(key, 3, dispatch_origin(1))
            .unwrap(),
        DispatchFailure::Retried { failed_attempts: 2 }
    );
    let DispatchFailure::Retired(retired) = dbio
        .record_dispatch_failure(key, 3, dispatch_origin(1))
        .unwrap()
    else {
        panic!("the third failure is the one it is given up on");
    };
    assert_eq!(retired.message_key, key);
    assert_eq!(retired.origin, dispatch_origin(1));
    assert_eq!(retired.failed_attempts, 3);

    // It has to leave the pending list, which the drain re-feeds every turn, or
    // a delivery that can never execute would be retried for ever.
    assert_eq!(
        dbio.get_pending_cross_zone_dispatches().unwrap(),
        vec![survivor],
        "giving up on a delivery takes its record out and leaves the others alone"
    );

    // A key with no record is not a give-up: nothing was counted and nothing was
    // abandoned. This is the shape of a delivery that settled and then failed a
    // later attempt.
    assert_eq!(
        dbio.record_dispatch_failure(key, 3, dispatch_origin(1))
            .unwrap(),
        DispatchFailure::Absent,
        "a failure against a retired delivery must not re-create its record"
    );
    assert_eq!(dbio.get_pending_cross_zone_dispatches().unwrap().len(), 1);
}

#[test]
fn a_retired_dispatch_moves_into_the_dead_letter_identified_by_its_origin() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    let record = dispatch_record(7);
    let key = record.message_key;
    let encoded_len = u32::try_from(record.transaction.len()).unwrap();
    dbio.add_pending_cross_zone_dispatches(vec![record])
        .unwrap();

    assert!(
        dbio.get_dead_letter_cross_zone_dispatches()
            .unwrap()
            .is_empty()
    );
    for _ in 0..3 {
        dbio.record_dispatch_failure(key, 3, dispatch_origin(7))
            .unwrap();
    }

    let dead_letters = dbio.get_dead_letter_cross_zone_dispatches().unwrap();
    assert_eq!(dead_letters.len(), 1);
    assert_eq!(dead_letters[0].message_key, key);
    assert_eq!(
        dead_letters[0].origin,
        dispatch_origin(7),
        "the peer coordinates are what let the message be read back off the peer channel"
    );
    assert_eq!(dead_letters[0].transaction_bytes, encoded_len);
    assert_eq!(dbio.get_dead_letter_cross_zone_dispatch_count().unwrap(), 1);
}

#[test]
fn a_dead_letter_is_dropped_once_its_delivery_settles_elsewhere() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    let record = dispatch_record(7);
    let key = record.message_key;
    dbio.add_pending_cross_zone_dispatches(vec![record])
        .unwrap();
    dbio.record_dispatch_failure(key, 1, dispatch_origin(7))
        .unwrap();
    assert_eq!(
        dbio.get_dead_letter_cross_zone_dispatches().unwrap().len(),
        1
    );

    // A delivery this node gave up on can still reach another sequencer's block.
    dbio.drop_settled_cross_zone_dispatches(&[key]).unwrap();
    assert!(
        dbio.get_dead_letter_cross_zone_dispatches()
            .unwrap()
            .is_empty()
    );

    // The count is how often this node gave up, which stays true whatever
    // happened next, and is what keeps the list readable as "still outstanding".
    assert_eq!(dbio.get_dead_letter_cross_zone_dispatch_count().unwrap(), 1);
}

#[test]
fn a_dead_letter_is_dropped_by_the_settlement_path_inside_a_store_update() {
    let temp_dir = tempdir().unwrap();
    let (dbio, genesis) = dbio_with_genesis(temp_dir.path());

    let record = dispatch_record(7);
    let key = record.message_key;
    dbio.add_pending_cross_zone_dispatches(vec![record])
        .unwrap();
    dbio.record_dispatch_failure(key, 1, dispatch_origin(7))
        .unwrap();
    assert_eq!(
        dbio.get_dead_letter_cross_zone_dispatches().unwrap().len(),
        1
    );

    // The ordinary route, unlike the standalone drop: a block carrying the
    // delivery becomes irreversible and the update that records that also
    // reconciles the dead letter, in the same batch.
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.store_update(&StoreUpdate {
        blocks: &[(&block2, true)],
        remove_dispatch_records: &[key],
        ..StoreUpdate::new(&state_with_balance(200))
    })
    .unwrap();

    assert!(
        dbio.get_dead_letter_cross_zone_dispatches()
            .unwrap()
            .is_empty()
    );
    assert_eq!(dbio.get_dead_letter_cross_zone_dispatch_count().unwrap(), 1);
}

#[test]
fn one_delivery_that_always_fails_takes_one_dead_letter_slot() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    // A watcher rebuilding a peer tip re-reads from genesis, so the same
    // never-executing delivery retires repeatedly (see `record_dispatch_failure`).
    let key = key_from_index(1);
    let other = key_from_index(2);
    dbio.add_pending_cross_zone_dispatches(vec![PendingCrossZoneDispatchRecord::recorded(
        other,
        vec![1, 2, 3, 4],
    )])
    .unwrap();
    dbio.record_dispatch_failure(other, 1, dispatch_origin(2))
        .unwrap();

    for _ in 0..5 {
        dbio.add_pending_cross_zone_dispatches(vec![PendingCrossZoneDispatchRecord::recorded(
            key,
            vec![1, 2, 3, 4],
        )])
        .unwrap();
        dbio.record_dispatch_failure(key, 1, dispatch_origin(1))
            .unwrap();
    }

    let dead_letters = dbio.get_dead_letter_cross_zone_dispatches().unwrap();
    assert_eq!(
        dead_letters.len(),
        2,
        "one entry per delivery, not per retirement"
    );
    assert_eq!(
        dead_letters[0].message_key, other,
        "the other message is not evicted"
    );

    // The count still measures give-ups, so the repetition remains visible.
    assert_eq!(dbio.get_dead_letter_cross_zone_dispatch_count().unwrap(), 6);
}

#[test]
fn dead_letters_evict_the_oldest_at_the_cap_but_keep_counting() {
    let temp_dir = tempdir().unwrap();
    let (dbio, _genesis) = dbio_with_genesis(temp_dir.path());

    let retirements = MAX_DEAD_LETTER_CROSS_ZONE_DISPATCHES + 3;
    for index in 0..retirements {
        let key = key_from_index(index);
        dbio.add_pending_cross_zone_dispatches(vec![PendingCrossZoneDispatchRecord::recorded(
            key,
            vec![1, 2, 3, 4],
        )])
        .unwrap();
        dbio.record_dispatch_failure(key, 1, dispatch_origin(1))
            .unwrap();
    }

    let dead_letters = dbio.get_dead_letter_cross_zone_dispatches().unwrap();
    assert_eq!(dead_letters.len(), MAX_DEAD_LETTER_CROSS_ZONE_DISPATCHES);
    assert_eq!(
        dead_letters[0].message_key,
        key_from_index(3),
        "the oldest retained entry is the fourth retirement, the first three having been evicted"
    );
    assert_eq!(
        dead_letters[dead_letters.len() - 1].message_key,
        key_from_index(retirements - 1),
        "the newest retirement is kept"
    );

    // What eviction must not do is hide that the evicted ones happened: a node
    // that lost hundreds of messages would otherwise look like one that lost the
    // cap.
    assert_eq!(
        dbio.get_dead_letter_cross_zone_dispatch_count().unwrap(),
        u64::try_from(retirements).unwrap()
    );
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
    dbio.atomic_update(
        &block2,
        None,
        &[],
        &state_with_balance(200),
        Some(b"cp-produced"),
    )
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
    dbio.atomic_update(&block2b, None, &[], &state_with_balance(400), None)
        .unwrap();

    let stored2 = dbio.get_block(2).unwrap().expect("block 2 is stored");
    assert_eq!(stored2.header.hash, block2b.header.hash);
    assert!(dbio.get_block(3).unwrap().is_none());
    let meta = dbio.latest_block_meta().unwrap().expect("meta is set");
    assert_eq!(meta.id, 2);
    assert_eq!(meta.hash, block2b.header.hash);
    assert_eq!(stored_balance(&dbio), 400);
}

/// A database nothing has written a genesis into answers "no chain yet" rather
/// than failing: every one of these was a hard `get` that errored on absence.
#[test]
fn an_unseeded_store_reports_no_chain() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dbio = RocksDBIO::open_or_create(dir.path()).expect("open");

    assert_eq!(dbio.get_meta_first_block_in_db().unwrap(), None);
    assert_eq!(dbio.get_meta_last_block_in_db().unwrap(), None);
    assert!(dbio.get_lee_state().unwrap().is_none());
    assert!(dbio.latest_block_meta().unwrap().is_none());
    assert!(dbio.get_final_snapshot().unwrap().is_none());
    assert!(!dbio.get_meta_is_first_block_set().unwrap());
    assert!(dbio.get_block(1).unwrap().is_none());
}

/// The first block written to an empty store starts its chain — the property
/// that lets a genesis go in as an ordinary block write.
#[test]
fn the_first_block_written_starts_the_chain() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dbio = RocksDBIO::open_or_create(dir.path()).expect("open");
    assert_eq!(dbio.get_meta_first_block_in_db().unwrap(), None);

    let genesis = produce_dummy_block(1, None, vec![]);
    dbio.atomic_update(&genesis, None, &[], &state_with_balance(100), None)
        .expect("seed");

    assert_eq!(dbio.get_meta_first_block_in_db().unwrap(), Some(1));
    assert_eq!(dbio.get_meta_last_block_in_db().unwrap(), Some(1));
    assert!(dbio.get_meta_is_first_block_set().unwrap());
    assert_eq!(
        dbio.get_block(1).unwrap().unwrap().header.hash,
        genesis.header.hash
    );

    // A later block extends the chain rather than restarting it.
    let second = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    dbio.atomic_update(&second, None, &[], &state_with_balance(100), None)
        .expect("extend");
    assert_eq!(dbio.get_meta_first_block_in_db().unwrap(), Some(1));
    assert_eq!(dbio.get_meta_last_block_in_db().unwrap(), Some(2));
}
