use std::{collections::HashSet, path::Path, sync::Arc};

use common::{
    HashType,
    block::{BedrockStatus, Block, BlockMeta, PeerChainTip},
    test_utils::{produce_dummy_block, produce_dummy_empty_transaction},
};
use kameo::actor::{ActorRef, Spawn as _};
use lee::{Account, AccountId, V03State};

use crate::{
    StorageActor,
    actor::{
        MAX_PENDING_CROSS_ZONE_DISPATCHES,
        entities::{DeadLetterDispatch, DeadLetterDispatches},
    },
    protocol::{
        AddPendingCrossZoneDispatches, AtomicUpdate, CrossZoneMessageKey, DeadLetterRequeue,
        DeleteCrossZonePeerFloor, DispatchFailure, DispatchOrigin, DropSettledCrossZoneDispatches,
        GetBlock, GetChannelCursor, GetCrossZonePeerFloorBytes, GetCrossZonePeerTip,
        GetDeadLetterDispatchCount, GetDeadLetterDispatches, GetFinalSnapshot, GetFirstBlockId,
        GetLastBlockId, GetLatestBlockMeta, GetLeeState, GetPendingCrossZoneDispatches,
        GetPendingDepositEvents, GetPublishedHighWater, GetTransactionByHash,
        GetZoneCheckpointBytes, PendingCrossZoneDispatchRecord, PendingDepositEventRecord,
        RaisePublishedHighWater, RecordDispatchFailure, RequeueDeadLetterDispatch,
        SetCrossZonePeerFloorBytes, SetCrossZonePeerTip, WithdrawalReconciliationKey,
    },
};

/// An update that touches no block, for filling in one bookkeeping field.
fn bookkeeping_update() -> AtomicUpdate {
    AtomicUpdate {
        checkpoint: None,
        blocks: Vec::new(),
        head_tip: None,
        head_state: Arc::new(V03State::new()),
        final_snapshot: None,
        finalized_up_to: None,
        new_deposit_events: Vec::new(),
        finalized_deposit_records: HashSet::new(),
        finalized_dispatch_records: HashSet::new(),
        consumed_withdrawals: HashSet::new(),
        new_withdraw_intents: HashSet::new(),
        zone_anchor: None,
        channel_cursor: None,
        lower_published_high_water: None,
    }
}

fn withdrawal_key(byte: u8) -> WithdrawalReconciliationKey {
    WithdrawalReconciliationKey {
        released_note_id: [byte; 32],
    }
}

fn deposit_record(byte: u8) -> PendingDepositEventRecord {
    PendingDepositEventRecord {
        deposit_op_id: HashType([byte; 32]),
        source_tx_hash: HashType([byte; 32]),
        amount: u64::from(byte),
        metadata: Vec::new(),
    }
}

/// An update pinning the head to `head_tip` and writing `blocks`, nothing else.
///
/// `from_block` supplies the head tip and the empty rest; only `blocks` varies,
/// and a shrink-only reorg carries none at all.
fn reorg_update(blocks: Vec<Block>, head_tip: &Block) -> AtomicUpdate {
    AtomicUpdate {
        blocks,
        ..AtomicUpdate::from_block(head_tip.clone(), Arc::new(V03State::new()))
    }
}

/// Asserts the tip read back off the store is `expected`. [`BlockMeta`] has no
/// [`PartialEq`], so the pair is compared field by field.
async fn assert_tip_is(storage_ref: &ActorRef<StorageActor>, expected: &Block) {
    let tip = storage_ref
        .ask(GetLatestBlockMeta)
        .await
        .expect("Failed to read the latest block meta")
        .expect("The store holds a chain");
    let expected = BlockMeta::from(expected);

    assert_eq!(tip.id, expected.id);
    assert_eq!(tip.hash, expected.hash);
}

/// Spawns an actor on a database at `path` seeded with `blocks`.
async fn spawn_with_blocks(path: &Path, blocks: Vec<Block>) -> ActorRef<StorageActor> {
    let storage_ref = StorageActor::spawn(StorageActor::new(path).expect("Failed to open db"));
    for block in blocks {
        storage_ref
            .ask(AtomicUpdate::from_block(block, Arc::new(V03State::new())))
            .await
            .expect("Failed to record a block");
    }
    storage_ref
}

fn marker_id() -> AccountId {
    AccountId::new([1; 32])
}

/// A state told apart by the marker account's balance, so a test can say which
/// of them a write persisted.
fn state_with_balance(balance: u128) -> Arc<V03State> {
    Arc::new(V03State::new().with_public_accounts([(
        marker_id(),
        Account {
            balance,
            ..Account::default()
        },
    )]))
}

/// A distinct message key per index, for filling the pending list.
fn key_from_index(index: usize) -> CrossZoneMessageKey {
    let mut key = [0_u8; 32];
    key[..8].copy_from_slice(&u64::try_from(index).expect("Test index fits").to_le_bytes());
    key
}

fn dispatch_origin(seed: u8) -> DispatchOrigin {
    DispatchOrigin {
        src_zone: [seed; 32],
        src_block_id: u64::from(seed),
        src_tx_index: u32::from(seed),
    }
}

/// The balance of the marker account in the stored head state.
async fn stored_balance(storage_ref: &ActorRef<StorageActor>) -> u128 {
    storage_ref
        .ask(GetLeeState)
        .await
        .expect("Failed to read the stored state")
        .expect("The store holds a chain")
        .get_account_by_id(marker_id())
        .balance
}

/// The stored block at `block_id`, which has to be there.
async fn stored_block(storage_ref: &ActorRef<StorageActor>, block_id: u64) -> Block {
    storage_ref
        .ask(GetBlock { block_id })
        .await
        .expect("Failed to read the block")
        .expect("The block is stored")
}

async fn pending_dispatch_keys(storage_ref: &ActorRef<StorageActor>) -> Vec<CrossZoneMessageKey> {
    let mut keys: Vec<_> = storage_ref
        .ask(GetPendingCrossZoneDispatches)
        .await
        .expect("Failed to read the pending dispatches")
        .into_iter()
        .map(|dispatch| dispatch.message_key)
        .collect();
    keys.sort_unstable();
    keys
}

/// Records one dispatch under `key` and fails it until it retires.
async fn retire_dispatch(
    storage_ref: &ActorRef<StorageActor>,
    key: CrossZoneMessageKey,
    origin: u8,
) {
    retire_dispatch_carrying(storage_ref, key, origin, vec![1, 2, 3, 4]).await;
}

/// [`retire_dispatch`] for a delivery whose size is what the test is about.
async fn retire_dispatch_carrying(
    storage_ref: &ActorRef<StorageActor>,
    key: CrossZoneMessageKey,
    origin: u8,
    transaction: Vec<u8>,
) {
    storage_ref
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![PendingCrossZoneDispatchRecord::recorded(key, transaction)],
        })
        .await
        .expect("Failed to record the dispatch");
    storage_ref
        .ask(RecordDispatchFailure {
            message_key: key,
            retire_at: 1,
            origin: dispatch_origin(origin),
        })
        .await
        .expect("Failed to retire the dispatch");
}

/// Holding the task's output keeps the stopped actor's state alive, which is exactly the
/// situation `on_stop` exists for: the lock has to be gone by the time the shutdown result
/// resolves, not by the time the state happens to be dropped.
#[tokio::test]
async fn stopped_actor_releases_the_database_lock() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let prepared = StorageActor::prepare();
    let actor_ref = prepared.actor_ref().clone();
    let join_handle = prepared.spawn(StorageActor::new(dir.path()).expect("Failed to open db"));

    actor_ref
        .stop_gracefully()
        .await
        .expect("Failed to stop the actor");
    actor_ref.wait_for_shutdown_with_result(|_| ()).await;

    StorageActor::new(dir.path()).expect("Database lock must be released once the actor stops");

    drop(join_handle);
}

#[tokio::test]
async fn recorded_transaction_is_looked_up_by_hash() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let transaction = produce_dummy_empty_transaction();
    let block = produce_dummy_block(1, None, vec![transaction.clone()]);
    let storage_ref =
        spawn_with_blocks(dir.path(), vec![produce_dummy_block(0, None, vec![])]).await;

    assert_eq!(
        storage_ref
            .ask(GetTransactionByHash {
                hash: transaction.hash()
            })
            .await
            .expect("Failed to look the transaction up"),
        None,
        "A transaction outside the chain has nowhere to be found"
    );

    storage_ref
        .ask(AtomicUpdate::from_block(block, Arc::new(V03State::new())))
        .await
        .expect("Failed to record the block");

    assert_eq!(
        storage_ref
            .ask(GetTransactionByHash {
                hash: transaction.hash()
            })
            .await
            .expect("Failed to look the transaction up"),
        Some((transaction, 1))
    );
}

/// The index lives only in memory, so a fresh actor has to build it off the
/// stored blocks rather than off the writes it has seen.
#[tokio::test]
async fn transaction_is_looked_up_on_a_reopened_database() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let transaction = produce_dummy_empty_transaction();

    let storage_weak = spawn_with_blocks(
        dir.path(),
        vec![
            produce_dummy_block(0, None, vec![]),
            produce_dummy_block(1, None, vec![transaction.clone()]),
        ],
    )
    .await
    .downgrade();
    storage_weak.wait_for_shutdown_with_result(|_| ()).await;

    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;
    assert_eq!(
        storage_ref
            .ask(GetTransactionByHash {
                hash: transaction.hash()
            })
            .await
            .expect("Failed to look the transaction up"),
        Some((transaction, 1))
    );
}

/// An update that replaces a stored block must not leave the transactions it
/// dropped reachable.
#[tokio::test]
async fn replaced_block_leaves_no_stale_index_entries() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let orphaned_transaction = produce_dummy_empty_transaction();
    let orphaned = produce_dummy_block(1, None, vec![orphaned_transaction.clone()]);
    let adopted = produce_dummy_block(1, Some(HashType([1; 32])), vec![]);

    let storage_ref = spawn_with_blocks(
        dir.path(),
        vec![produce_dummy_block(0, None, vec![]), orphaned],
    )
    .await;
    // The index starts out holding the chain the adopted block replaces.
    storage_ref
        .ask(GetTransactionByHash {
            hash: orphaned_transaction.hash(),
        })
        .await
        .expect("Failed to look the transaction up")
        .expect("The orphaned block is the stored one so far");

    storage_ref
        .ask(AtomicUpdate::from_block(adopted, Arc::new(V03State::new())))
        .await
        .expect("Failed to apply the update");

    assert_eq!(
        storage_ref
            .ask(GetTransactionByHash {
                hash: orphaned_transaction.hash()
            })
            .await
            .expect("Failed to look the transaction up"),
        None
    );
}

/// A shorter competing chain wins: block 1 is replaced and block 2 gets no
/// replacement, so the store is left holding a block above its own head.
#[tokio::test]
async fn net_shortening_reorg_drops_stale_blocks() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let genesis = produce_dummy_block(0, None, vec![]);
    let block1a = produce_dummy_block(1, Some(genesis.header.hash), vec![]);
    let block2 = produce_dummy_block(2, Some(block1a.header.hash), vec![]);
    let block1b = produce_dummy_block(1, Some(HashType([9; 32])), vec![]);

    let storage_ref = spawn_with_blocks(dir.path(), vec![genesis, block1a, block2]).await;

    storage_ref
        .ask(reorg_update(vec![block1b.clone()], &block1b))
        .await
        .expect("Failed to apply the reorg");

    assert_eq!(
        storage_ref
            .ask(GetBlock { block_id: 1 })
            .await
            .expect("Failed to read block 1")
            .expect("Block 1 is stored")
            .header
            .hash,
        block1b.header.hash
    );
    assert!(
        storage_ref
            .ask(GetBlock { block_id: 2 })
            .await
            .expect("Failed to read block 2")
            .is_none(),
        "A block above the new head must be deleted, or the tip read back is the orphan's"
    );
    assert_tip_is(&storage_ref, &block1b).await;
}

/// An orphan-only update: block 2 falls off the branch with no replacement, so
/// the update carries no block at all and only the pinned tip says where the
/// head went.
#[tokio::test]
async fn shrink_only_reorg_rewinds_the_tip() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let orphaned_transaction = produce_dummy_empty_transaction();
    let genesis = produce_dummy_block(0, None, vec![]);
    let block1 = produce_dummy_block(1, Some(genesis.header.hash), vec![]);
    let block2 = produce_dummy_block(
        2,
        Some(block1.header.hash),
        vec![orphaned_transaction.clone()],
    );

    let storage_ref = spawn_with_blocks(dir.path(), vec![genesis, block1.clone(), block2]).await;

    storage_ref
        .ask(reorg_update(Vec::new(), &block1))
        .await
        .expect("Failed to apply the rewind");

    assert!(
        storage_ref
            .ask(GetBlock { block_id: 2 })
            .await
            .expect("Failed to read block 2")
            .is_none(),
        "The orphaned block must not survive the tip rewind"
    );
    assert_tip_is(&storage_ref, &block1).await;
    assert_eq!(
        storage_ref
            .ask(GetTransactionByHash {
                hash: orphaned_transaction.hash()
            })
            .await
            .expect("Failed to look the transaction up"),
        None,
        "The swept block's transactions must leave the index with it"
    );
}

/// The reconciliation is a set membership test, so an intent has to outlive the
/// update that raised it and every later update that touches the set.
#[tokio::test]
async fn withdraw_intents_survive_later_updates() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    // Raised one at a time, as the produce path does: each update must leave the
    // earlier intents alone.
    for byte in 1..=3 {
        storage_ref
            .ask(AtomicUpdate {
                new_withdraw_intents: HashSet::from([withdrawal_key(byte)]),
                ..bookkeeping_update()
            })
            .await
            .expect("Failed to raise the intent");
    }

    let outcome = storage_ref
        .ask(AtomicUpdate {
            consumed_withdrawals: (1..=3).map(withdrawal_key).collect(),
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to reconcile the events");

    assert!(
        outcome.unmatched_withdrawals.is_empty(),
        "Every reported note was published by this node, so none is unmatched"
    );
}

/// The outcome reports the events this node cannot account for — never the
/// intents it is still waiting on.
#[tokio::test]
async fn withdraw_event_without_an_intent_is_reported_unmatched() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    storage_ref
        .ask(AtomicUpdate {
            new_withdraw_intents: HashSet::from([withdrawal_key(1)]),
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to raise the intent");

    // Note 2 was never published here; note 1 is still outstanding and must not
    // be reported just because another event arrived.
    let outcome = storage_ref
        .ask(AtomicUpdate {
            consumed_withdrawals: HashSet::from([withdrawal_key(2)]),
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to reconcile the event");

    assert_eq!(outcome.unmatched_withdrawals, vec![withdrawal_key(2)]);
}

/// A settled intent is gone for good, so a re-delivered event has nothing left
/// to match.
#[tokio::test]
async fn consumed_withdrawal_is_not_matched_twice() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    storage_ref
        .ask(AtomicUpdate {
            new_withdraw_intents: HashSet::from([withdrawal_key(1)]),
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to raise the intent");
    let first = storage_ref
        .ask(AtomicUpdate {
            consumed_withdrawals: HashSet::from([withdrawal_key(1)]),
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to reconcile the event");
    assert!(first.unmatched_withdrawals.is_empty());

    let second = storage_ref
        .ask(AtomicUpdate {
            consumed_withdrawals: HashSet::from([withdrawal_key(1)]),
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to reconcile the re-delivery");

    assert_eq!(second.unmatched_withdrawals, vec![withdrawal_key(1)]);
}

/// `accepted_deposits` is what the caller logs as newly owed mints, so a
/// re-delivery of an already-pending deposit must count for nothing.
#[tokio::test]
async fn only_newly_recorded_deposits_are_counted() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    let first = storage_ref
        .ask(AtomicUpdate {
            new_deposit_events: vec![deposit_record(1), deposit_record(2)],
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to record the deposits");
    assert_eq!(first.accepted_deposits, 2);

    // One already pending, one new: only the new one is owed.
    let second = storage_ref
        .ask(AtomicUpdate {
            new_deposit_events: vec![deposit_record(2), deposit_record(3)],
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to record the deposits");
    assert_eq!(second.accepted_deposits, 1);

    let pending = storage_ref
        .ask(GetPendingDepositEvents)
        .await
        .expect("Failed to read the pending deposits");
    assert_eq!(pending.len(), 3);
}

/// Backfill can deliver a deposit and its finalization in one event: the record
/// is owed nothing, and counting it would log a mint that never comes.
#[tokio::test]
async fn deposit_finalized_in_the_same_update_is_never_recorded() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    let outcome = storage_ref
        .ask(AtomicUpdate {
            new_deposit_events: vec![deposit_record(1)],
            finalized_deposit_records: HashSet::from([HashType([1; 32])]),
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to apply the update");

    assert_eq!(outcome.accepted_deposits, 0);
    assert!(
        storage_ref
            .ask(GetPendingDepositEvents)
            .await
            .expect("Failed to read the pending deposits")
            .is_empty()
    );
}

/// The drain re-feeds every pending record, so a delivery that is irreversible
/// has to lose its record or the transaction is re-included forever.
#[tokio::test]
async fn settled_dispatch_drops_its_pending_record() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    storage_ref
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![
                PendingCrossZoneDispatchRecord::recorded([1; 32], vec![1]),
                PendingCrossZoneDispatchRecord::recorded([2; 32], vec![2]),
            ],
        })
        .await
        .expect("Failed to record the dispatches");

    storage_ref
        .ask(AtomicUpdate {
            finalized_dispatch_records: HashSet::from_iter([[1; 32]]),
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to settle the dispatch");

    let pending = storage_ref
        .ask(GetPendingCrossZoneDispatches)
        .await
        .expect("Failed to read the pending dispatches");
    assert_eq!(
        pending
            .iter()
            .map(|dispatch| dispatch.message_key)
            .collect::<Vec<_>>(),
        vec![[2; 32]],
        "Only the settled delivery loses its record"
    );
}

/// Every sequencer gives up alone, against its own head, so a delivery this one
/// abandoned can still reach another's block. The retained record goes; the
/// count of how often this node gave up does not.
#[tokio::test]
async fn settled_dispatch_reconciles_its_dead_letter_but_not_the_count() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    storage_ref
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![PendingCrossZoneDispatchRecord::recorded([1; 32], vec![1])],
        })
        .await
        .expect("Failed to record the dispatch");
    storage_ref
        .ask(RecordDispatchFailure {
            message_key: [1; 32],
            retire_at: 1,
            origin: DispatchOrigin {
                src_zone: [7; 32],
                src_block_id: 3,
                src_tx_index: 0,
            },
        })
        .await
        .expect("Failed to retire the dispatch");
    assert_eq!(
        storage_ref
            .ask(GetDeadLetterDispatches)
            .await
            .expect("Failed to read the dead letters")
            .len(),
        1
    );

    // Another sequencer carried the delivery into a block that just finalized.
    storage_ref
        .ask(AtomicUpdate {
            finalized_dispatch_records: HashSet::from_iter([[1; 32]]),
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to settle the dispatch");

    assert!(
        storage_ref
            .ask(GetDeadLetterDispatches)
            .await
            .expect("Failed to read the dead letters")
            .is_empty(),
        "A delivery that settled elsewhere is no longer worth retaining"
    );
    assert_eq!(
        storage_ref
            .ask(GetDeadLetterDispatchCount)
            .await
            .expect("Failed to read the dead letter count"),
        1,
        "This node still gave up once, and the count says how often that happened"
    );
}

/// The block and the state it produced are one write: a store holding one
/// without the other tears the chain against its own state.
#[tokio::test]
async fn block_and_state_are_stored_together() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    let block = produce_dummy_block(1, None, vec![]);
    storage_ref
        .ask(AtomicUpdate::from_block(
            block.clone(),
            state_with_balance(200),
        ))
        .await
        .expect("Failed to record the block");

    let stored = stored_block(&storage_ref, 1).await;
    assert_eq!(stored.header.hash, block.header.hash);
    assert!(
        matches!(stored.bedrock_status, BedrockStatus::Pending),
        "An update that finalizes nothing leaves the block pending"
    );
    assert_tip_is(&storage_ref, &block).await;
    assert_eq!(stored_balance(&storage_ref).await, 200);
}

/// Finality travels as one watermark rather than per block, so an update
/// carrying several has to mark exactly the ones at or below it.
#[tokio::test]
async fn finalized_up_to_marks_only_the_blocks_it_covers() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let genesis = produce_dummy_block(1, None, vec![]);
    let storage_ref = spawn_with_blocks(dir.path(), vec![genesis.clone()]).await;

    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
    storage_ref
        .ask(AtomicUpdate {
            blocks: vec![block2.clone(), block3.clone()],
            head_tip: Some(BlockMeta::from(&block3)),
            finalized_up_to: Some(2),
            ..AtomicUpdate::from_block(block3.clone(), state_with_balance(300))
        })
        .await
        .expect("Failed to apply the update");

    assert!(matches!(
        stored_block(&storage_ref, 2).await.bedrock_status,
        BedrockStatus::Finalized
    ));
    assert!(
        matches!(
            stored_block(&storage_ref, 3).await.bedrock_status,
            BedrockStatus::Pending
        ),
        "A block above the watermark is not irreversible yet"
    );

    // Meta and state land together on the last block of the batch.
    assert_tip_is(&storage_ref, &block3).await;
    assert_eq!(stored_balance(&storage_ref).await, 300);
}

/// Finality is irreversible, so a later write of the same block must not take
/// it back — the caller only ever raises the watermark.
#[tokio::test]
async fn a_rewritten_block_keeps_the_finalized_status_it_had() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let genesis = produce_dummy_block(1, None, vec![]);
    let storage_ref = spawn_with_blocks(dir.path(), vec![genesis.clone()]).await;

    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    storage_ref
        .ask(AtomicUpdate {
            finalized_up_to: Some(2),
            ..AtomicUpdate::from_block(block2.clone(), state_with_balance(200))
        })
        .await
        .expect("Failed to finalize the block");

    storage_ref
        .ask(AtomicUpdate::from_block(block2, state_with_balance(300)))
        .await
        .expect("Failed to rewrite the block");

    assert!(matches!(
        stored_block(&storage_ref, 2).await.bedrock_status,
        BedrockStatus::Finalized
    ));
    assert_eq!(
        stored_balance(&storage_ref).await,
        200,
        "A rewrite of the block the store already holds moves no chain, and must not rewrite the state"
    );
}

/// Every follow event carries a checkpoint and most carry nothing else, so the
/// idle path must not pay for a whole state serialization.
#[tokio::test]
async fn a_checkpoint_only_update_does_not_rewrite_the_head_state() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), Vec::new()).await;

    let genesis = produce_dummy_block(1, None, vec![]);
    storage_ref
        .ask(AtomicUpdate::from_block(
            genesis.clone(),
            state_with_balance(200),
        ))
        .await
        .expect("Failed to record the genesis block");

    // The chain stands still: the tip is the block already stored, and no block
    // comes with the update. The state it carries is ignored.
    storage_ref
        .ask(AtomicUpdate {
            checkpoint: Some(b"cp-idle".to_vec()),
            head_tip: Some(BlockMeta::from(&genesis)),
            head_state: state_with_balance(999),
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to apply the checkpoint-only update");

    assert_eq!(
        storage_ref
            .ask(GetZoneCheckpointBytes)
            .await
            .expect("Failed to read the checkpoint"),
        Some(b"cp-idle".to_vec()),
        "The checkpoint still has to land"
    );
    assert_eq!(stored_balance(&storage_ref).await, 200);
}

/// The snapshot is what a restart re-anchors on, and it is stored apart from the
/// head state so a reorg above the final tier cannot drag it along.
#[tokio::test]
async fn final_snapshot_round_trips_and_is_kept_apart_from_the_head_state() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let genesis = produce_dummy_block(1, None, vec![]);
    let storage_ref = spawn_with_blocks(dir.path(), vec![genesis.clone()]).await;

    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let final_meta = BlockMeta::from(&block2);
    storage_ref
        .ask(AtomicUpdate {
            final_snapshot: Some((state_with_balance(200), final_meta)),
            finalized_up_to: Some(2),
            ..AtomicUpdate::from_block(block2.clone(), state_with_balance(300))
        })
        .await
        .expect("Failed to apply the update");

    let (final_state, meta) = storage_ref
        .ask(GetFinalSnapshot)
        .await
        .expect("Failed to read the final snapshot")
        .expect("The final snapshot is stored");
    assert_eq!(meta.id, 2);
    assert_eq!(meta.hash, block2.header.hash);
    assert_eq!(final_state.get_account_by_id(marker_id()).balance, 200);
    assert_eq!(stored_balance(&storage_ref).await, 300);
}

/// The checkpoint is the zone-sdk's resume cursor, so an event that writes no
/// block still has to land it — a restart would otherwise resume past the
/// orphan it covers.
#[tokio::test]
async fn checkpoint_lands_with_an_update_carrying_no_block() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    storage_ref
        .ask(AtomicUpdate {
            checkpoint: Some(b"cp-orphan".to_vec()),
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to apply the update");

    assert_eq!(
        storage_ref
            .ask(GetZoneCheckpointBytes)
            .await
            .expect("Failed to read the checkpoint")
            .as_deref(),
        Some(b"cp-orphan".as_slice())
    );
}

/// A database nothing has written a chain into answers "nothing yet" rather
/// than failing.
#[tokio::test]
async fn an_unseeded_store_reports_no_chain() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    assert_eq!(
        storage_ref
            .ask(GetFirstBlockId)
            .await
            .expect("Failed to read the first block id"),
        None
    );
    assert_eq!(
        storage_ref
            .ask(GetLastBlockId)
            .await
            .expect("Failed to read the last block id"),
        None
    );
    assert!(
        storage_ref
            .ask(GetLatestBlockMeta)
            .await
            .expect("Failed to read the latest block meta")
            .is_none()
    );
    assert!(
        storage_ref
            .ask(GetLeeState)
            .await
            .expect("Failed to read the state")
            .is_none()
    );
    assert!(
        storage_ref
            .ask(GetFinalSnapshot)
            .await
            .expect("Failed to read the final snapshot")
            .is_none()
    );
    assert!(
        storage_ref
            .ask(GetBlock { block_id: 1 })
            .await
            .expect("Failed to read block 1")
            .is_none()
    );
}

/// The property that lets a genesis go in as an ordinary block write.
#[tokio::test]
async fn the_first_block_written_starts_the_chain() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let genesis = produce_dummy_block(1, None, vec![]);
    let storage_ref = spawn_with_blocks(dir.path(), vec![genesis.clone()]).await;

    assert_eq!(
        storage_ref
            .ask(GetFirstBlockId)
            .await
            .expect("Failed to read the first block id"),
        Some(1)
    );
    assert_eq!(
        storage_ref
            .ask(GetLastBlockId)
            .await
            .expect("Failed to read the last block id"),
        Some(1)
    );

    // A later block extends the chain rather than restarting it.
    let second = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    storage_ref
        .ask(AtomicUpdate::from_block(second, Arc::new(V03State::new())))
        .await
        .expect("Failed to record the second block");

    assert_eq!(
        storage_ref
            .ask(GetFirstBlockId)
            .await
            .expect("Failed to read the first block id"),
        Some(1)
    );
    assert_eq!(
        storage_ref
            .ask(GetLastBlockId)
            .await
            .expect("Failed to read the last block id"),
        Some(2)
    );
}

/// A record goes by its own op id, never because some other deposit finalized.
#[tokio::test]
async fn only_the_finalized_deposit_record_is_dropped() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    storage_ref
        .ask(AtomicUpdate {
            new_deposit_events: vec![deposit_record(1), deposit_record(2)],
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to record the deposits");

    storage_ref
        .ask(AtomicUpdate {
            finalized_deposit_records: HashSet::from([HashType([1; 32])]),
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to settle the deposit");

    assert_eq!(
        storage_ref
            .ask(GetPendingDepositEvents)
            .await
            .expect("Failed to read the pending deposits"),
        vec![deposit_record(2)]
    );
}

/// The floor and the tip of one peer are keyed by the same zone id and differ
/// only in what they are, so a write of either must leave the other alone: a
/// shared key would let one peer's chain decide which blocks another peer's
/// watcher accepts.
#[tokio::test]
async fn peer_floor_and_tip_are_kept_per_peer_without_colliding() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let peer_a = [1_u8; 32];
    let peer_b = [2_u8; 32];
    let tip_a = PeerChainTip {
        block_id: 7,
        block_hash: HashType([9; 32]),
    };
    let tip_b = PeerChainTip {
        block_id: 3,
        block_hash: HashType([4; 32]),
    };

    let storage_weak = {
        let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;
        assert_eq!(
            storage_ref
                .ask(GetCrossZonePeerTip { peer_zone: peer_a })
                .await
                .expect("Failed to read the peer tip"),
            None
        );

        storage_ref
            .ask(SetCrossZonePeerFloorBytes {
                peer_zone: peer_a,
                bytes: 11_u64.to_le_bytes().to_vec(),
            })
            .await
            .expect("Failed to write the peer floor");
        for (peer_zone, tip) in [(peer_a, tip_a), (peer_b, tip_b)] {
            storage_ref
                .ask(SetCrossZonePeerTip { peer_zone, tip })
                .await
                .expect("Failed to write the peer tip");
        }

        assert_eq!(
            storage_ref
                .ask(GetCrossZonePeerTip { peer_zone: peer_a })
                .await
                .expect("Failed to read the peer tip"),
            Some(tip_a)
        );
        assert_eq!(
            storage_ref
                .ask(GetCrossZonePeerTip { peer_zone: peer_b })
                .await
                .expect("Failed to read the peer tip"),
            Some(tip_b)
        );
        assert_eq!(
            storage_ref
                .ask(GetCrossZonePeerFloorBytes { peer_zone: peer_a })
                .await
                .expect("Failed to read the peer floor"),
            Some(11_u64.to_le_bytes().to_vec()),
            "The tip must not land in the floor's key space"
        );

        // Clearing the floor is how a watcher with no tip rebuilds one, so it
        // has to leave the tip standing.
        storage_ref
            .ask(DeleteCrossZonePeerFloor { peer_zone: peer_a })
            .await
            .expect("Failed to clear the peer floor");
        assert_eq!(
            storage_ref
                .ask(GetCrossZonePeerFloorBytes { peer_zone: peer_a })
                .await
                .expect("Failed to read the peer floor"),
            None
        );
        assert_eq!(
            storage_ref
                .ask(GetCrossZonePeerTip { peer_zone: peer_a })
                .await
                .expect("Failed to read the peer tip"),
            Some(tip_a)
        );

        storage_ref.downgrade()
    };
    storage_weak.wait_for_shutdown_with_result(|_| ()).await;

    // On disk, not in memory: a watcher that re-anchored on restart would take
    // whatever block reached it first, which is the id an attack picks.
    let reopened = spawn_with_blocks(dir.path(), vec![]).await;
    assert_eq!(
        reopened
            .ask(GetCrossZonePeerTip { peer_zone: peer_a })
            .await
            .expect("Failed to read the peer tip"),
        Some(tip_a)
    );
    assert_eq!(
        reopened
            .ask(GetCrossZonePeerTip { peer_zone: peer_b })
            .await
            .expect("Failed to read the peer tip"),
        Some(tip_b)
    );
}

/// The watcher re-reads a slot it stalled on, so the same delivery arrives
/// again; recording it twice would double-count its failed attempts.
#[tokio::test]
async fn pending_dispatches_dedupe_by_message_key() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    let record = PendingCrossZoneDispatchRecord::recorded([1; 32], vec![1]);
    assert_eq!(
        storage_ref
            .ask(AddPendingCrossZoneDispatches {
                dispatches: vec![record.clone()],
            })
            .await
            .expect("Failed to record the dispatch"),
        1
    );
    assert_eq!(
        storage_ref
            .ask(AddPendingCrossZoneDispatches {
                dispatches: vec![
                    record,
                    PendingCrossZoneDispatchRecord::recorded([2; 32], vec![2]),
                ],
            })
            .await
            .expect("Failed to record the dispatches"),
        1,
        "Only the delivery not already held is newly recorded"
    );

    assert_eq!(
        pending_dispatch_keys(&storage_ref).await,
        vec![[1; 32], [2; 32]]
    );
}

/// What fills this list is chosen by peer zones, so the bound is what stops a
/// peer deciding how large our store gets. Refusing the whole write leaves the
/// watcher's floor where it is, so the slot is read again later and nothing is
/// lost.
#[tokio::test]
async fn recording_past_the_cap_writes_nothing() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    let full: Vec<_> = (0..MAX_PENDING_CROSS_ZONE_DISPATCHES)
        .map(|index| PendingCrossZoneDispatchRecord::recorded(key_from_index(index), vec![0; 4]))
        .collect();
    assert_eq!(
        storage_ref
            .ask(AddPendingCrossZoneDispatches { dispatches: full })
            .await
            .expect("Failed to fill the pending list"),
        MAX_PENDING_CROSS_ZONE_DISPATCHES
    );

    let over = PendingCrossZoneDispatchRecord::recorded(
        key_from_index(MAX_PENDING_CROSS_ZONE_DISPATCHES),
        vec![0; 4],
    );
    assert!(
        storage_ref
            .ask(AddPendingCrossZoneDispatches {
                dispatches: vec![over],
            })
            .await
            .is_err(),
        "Recording past the cap must fail so the caller holds its floor"
    );
    assert_eq!(
        pending_dispatch_keys(&storage_ref).await.len(),
        MAX_PENDING_CROSS_ZONE_DISPATCHES,
        "A refused write must leave the records untouched"
    );

    // Re-offering only what is already held is not growth, so it still succeeds.
    assert_eq!(
        storage_ref
            .ask(AddPendingCrossZoneDispatches {
                dispatches: vec![PendingCrossZoneDispatchRecord::recorded(
                    key_from_index(0),
                    vec![0; 4]
                )],
            })
            .await
            .expect("Re-offering a held delivery is not growth"),
        0
    );
}

/// On disk, not in memory: the records are what stand between the watcher's
/// durable read floor and a lost delivery across a restart.
#[tokio::test]
async fn pending_dispatches_survive_a_reopen() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");

    let storage_weak = {
        let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;
        storage_ref
            .ask(AddPendingCrossZoneDispatches {
                dispatches: vec![
                    PendingCrossZoneDispatchRecord::recorded([1; 32], vec![1]),
                    PendingCrossZoneDispatchRecord::recorded([2; 32], vec![2]),
                ],
            })
            .await
            .expect("Failed to record the dispatches");
        storage_ref.downgrade()
    };
    storage_weak.wait_for_shutdown_with_result(|_| ()).await;

    let reopened = spawn_with_blocks(dir.path(), vec![]).await;
    assert_eq!(
        pending_dispatch_keys(&reopened).await,
        vec![[1; 32], [2; 32]]
    );
}

/// The watcher re-reads a slot it already consumed and re-records a delivery
/// that settled long ago. Its key will never appear in a future block, so the
/// store-update path cannot reach it and this is the only thing that does.
#[tokio::test]
async fn settled_dispatches_are_dropped_outside_an_update() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    storage_ref
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![
                PendingCrossZoneDispatchRecord::recorded([1; 32], vec![1]),
                PendingCrossZoneDispatchRecord::recorded([2; 32], vec![2]),
            ],
        })
        .await
        .expect("Failed to record the dispatches");

    storage_ref
        .ask(DropSettledCrossZoneDispatches {
            message_keys: HashSet::from([[1; 32]]),
        })
        .await
        .expect("Failed to drop the settled delivery");
    assert_eq!(pending_dispatch_keys(&storage_ref).await, vec![[2; 32]]);

    // Dropping one that is already gone is a no-op, not an error.
    storage_ref
        .ask(DropSettledCrossZoneDispatches {
            message_keys: HashSet::from([[1; 32]]),
        })
        .await
        .expect("Dropping a delivery that is already gone is not an error");
    assert_eq!(pending_dispatch_keys(&storage_ref).await, vec![[2; 32]]);
}

/// A delivery is retried until the caller's limit, then given up on: it leaves
/// the pending list the drain re-feeds, or one that can never execute would be
/// retried for ever.
#[tokio::test]
async fn dispatch_failures_are_counted_until_the_record_retires() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    let transaction = vec![7; 4];
    let key = [7; 32];
    storage_ref
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![
                PendingCrossZoneDispatchRecord::recorded(key, transaction.clone()),
                PendingCrossZoneDispatchRecord::recorded([8; 32], vec![8]),
            ],
        })
        .await
        .expect("Failed to record the dispatches");

    let fail = async || {
        storage_ref
            .ask(RecordDispatchFailure {
                message_key: key,
                retire_at: 3,
                origin: dispatch_origin(7),
            })
            .await
            .expect("Failed to record the failure")
    };

    assert_eq!(
        fail().await,
        DispatchFailure::Retried { failed_attempts: 1 },
        "A failure short of the limit is counted, not given up on"
    );
    assert_eq!(
        fail().await,
        DispatchFailure::Retried { failed_attempts: 2 }
    );

    let DispatchFailure::Retired(retired) = fail().await else {
        panic!("The third failure is the one it is given up on");
    };
    assert_eq!(retired.message_key, key);
    assert_eq!(
        retired.origin,
        dispatch_origin(7),
        "The peer coordinates are what let the message be read back off the peer channel"
    );
    assert_eq!(retired.failed_attempts, 3);
    assert_eq!(
        retired.transaction, transaction,
        "The record keeps the bytes a requeue restores"
    );

    assert_eq!(
        pending_dispatch_keys(&storage_ref).await,
        vec![[8; 32]],
        "Giving up on a delivery takes its record out and leaves the others alone"
    );

    // A key with no record is not a give-up: nothing was counted and nothing was
    // abandoned. This is the shape of a delivery that settled and then failed a
    // later attempt.
    assert_eq!(
        fail().await,
        DispatchFailure::Absent,
        "A failure against a retired delivery must not re-create its record"
    );
    assert_eq!(pending_dispatch_keys(&storage_ref).await, vec![[8; 32]]);
}

/// A watcher rebuilding a peer tip re-reads from genesis, so the same
/// never-executing delivery retires over and over.
#[tokio::test]
async fn one_delivery_that_always_fails_takes_one_dead_letter_slot() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    retire_dispatch(&storage_ref, key_from_index(2), 2).await;
    for _ in 0..5 {
        retire_dispatch(&storage_ref, key_from_index(1), 1).await;
    }

    let dead_letters = storage_ref
        .ask(GetDeadLetterDispatches)
        .await
        .expect("Failed to read the dead letters");
    assert_eq!(
        dead_letters.len(),
        2,
        "One entry per delivery, not per retirement"
    );
    assert_eq!(
        dead_letters[0].message_key,
        key_from_index(2),
        "The other message is not evicted"
    );

    assert_eq!(
        storage_ref
            .ask(GetDeadLetterDispatchCount)
            .await
            .expect("Failed to read the dead letter count"),
        6,
        "The count still measures give-ups, so the repetition stays visible"
    );
}

/// What eviction must not do is hide that the evicted ones happened: a node
/// that lost hundreds of deliveries would otherwise look like one that lost the
/// cap.
#[tokio::test]
async fn dead_letters_evict_the_oldest_at_the_cap_but_keep_counting() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    let retirements = DeadLetterDispatches::MAX_DEAD_LETTER_CROSS_ZONE_DISPATCHES + 3;
    for index in 0..retirements {
        retire_dispatch(&storage_ref, key_from_index(index), 1).await;
    }

    let dead_letters = storage_ref
        .ask(GetDeadLetterDispatches)
        .await
        .expect("Failed to read the dead letters");
    assert_eq!(
        dead_letters.len(),
        DeadLetterDispatches::MAX_DEAD_LETTER_CROSS_ZONE_DISPATCHES
    );
    assert_eq!(
        dead_letters[0].message_key,
        key_from_index(3),
        "The oldest retained entry is the fourth retirement, the first three having been evicted"
    );
    assert_eq!(
        dead_letters[dead_letters.len() - 1].message_key,
        key_from_index(retirements - 1),
        "The newest retirement is kept"
    );

    assert_eq!(
        storage_ref
            .ask(GetDeadLetterDispatchCount)
            .await
            .expect("Failed to read the dead letter count"),
        u64::try_from(retirements).expect("Test retirement count fits")
    );
}

/// The cursor has to outlive the process: a restart that cannot recover it has
/// nothing to chain the next publish onto.
#[tokio::test]
async fn channel_cursor_survives_a_reopen() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    assert_eq!(
        storage_ref
            .ask(GetChannelCursor)
            .await
            .expect("Failed to read the channel cursor"),
        None,
        "A store written without a cursor has none to report"
    );

    storage_ref
        .ask(AtomicUpdate {
            channel_cursor: Some([7; 32]),
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to apply the update");
    storage_ref
        .ask(bookkeeping_update())
        .await
        .expect("Failed to apply the update");

    let storage_weak = storage_ref.downgrade();
    drop(storage_ref);
    storage_weak.wait_for_shutdown_with_result(|_| ()).await;

    let reopened_ref = spawn_with_blocks(dir.path(), vec![]).await;
    assert_eq!(
        reopened_ref
            .ask(GetChannelCursor)
            .await
            .expect("Failed to read the channel cursor"),
        Some([7; 32]),
        "The cursor comes back after a restart, and an update carrying none left it alone"
    );
}

/// The mark otherwise only rises. Lowering it frees a height to be inscribed
/// again, which is only ever right for a block the channel dropped, so an
/// update naming a height above the mark must not raise it by the back door.
#[tokio::test]
async fn published_high_water_is_lowered_only_from_above() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    storage_ref
        .ask(RaisePublishedHighWater { block_id: 9 })
        .await
        .expect("Failed to raise the high water mark");

    let lower_to = async |block_id| {
        storage_ref
            .ask(AtomicUpdate {
                lower_published_high_water: Some(block_id),
                ..bookkeeping_update()
            })
            .await
            .expect("Failed to apply the update");
        storage_ref
            .ask(GetPublishedHighWater)
            .await
            .expect("Failed to read the high water mark")
    };

    assert_eq!(lower_to(4).await, Some(4));
    assert_eq!(
        lower_to(7).await,
        Some(4),
        "A height the mark is already below leaves it where it is"
    );
}

/// The operator move for a delivery whose cause of failure has cleared: a
/// raised mint cap, a fixed target program.
#[tokio::test]
async fn a_requeued_dead_letter_returns_to_pending_with_a_clean_count() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    let transaction = vec![1, 2, 3, 4];
    retire_dispatch(&storage_ref, [7; 32], 7).await;

    assert_eq!(
        storage_ref
            .ask(RequeueDeadLetterDispatch {
                message_key: [7; 32]
            })
            .await
            .expect("Failed to requeue the dead letter"),
        DeadLetterRequeue::Requeued
    );

    let pending = storage_ref
        .ask(GetPendingCrossZoneDispatches)
        .await
        .expect("Failed to read the pending dispatches");
    assert_eq!(
        pending,
        vec![PendingCrossZoneDispatchRecord::recorded(
            [7; 32],
            transaction
        )],
        "The bytes survive the round trip through the dead letter, and the attempt count restarts"
    );

    assert!(
        storage_ref
            .ask(GetDeadLetterDispatches)
            .await
            .expect("Failed to read the dead letters")
            .is_empty()
    );
    assert_eq!(
        storage_ref
            .ask(GetDeadLetterDispatchCount)
            .await
            .expect("Failed to read the dead letter count"),
        1,
        "Requeueing does not unmake the giving up"
    );
}

#[tokio::test]
async fn requeueing_an_unknown_key_reports_not_found() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    assert_eq!(
        storage_ref
            .ask(RequeueDeadLetterDispatch {
                message_key: [9; 32]
            })
            .await
            .expect("Failed to requeue the dead letter"),
        DeadLetterRequeue::NotFound
    );
    assert!(pending_dispatch_keys(&storage_ref).await.is_empty());
}

/// The watcher re-adds a pending record whenever it re-reads a slot it has
/// already consumed, so a requeue can race a delivery that is pending again.
#[tokio::test]
async fn requeueing_a_delivery_already_pending_again_only_drops_the_dead_letter() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    retire_dispatch(&storage_ref, [7; 32], 7).await;
    storage_ref
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![PendingCrossZoneDispatchRecord::recorded([7; 32], vec![9])],
        })
        .await
        .expect("Failed to re-record the dispatch");
    storage_ref
        .ask(RecordDispatchFailure {
            message_key: [7; 32],
            retire_at: 3,
            origin: dispatch_origin(7),
        })
        .await
        .expect("Failed to record the failure");

    assert_eq!(
        storage_ref
            .ask(RequeueDeadLetterDispatch {
                message_key: [7; 32]
            })
            .await
            .expect("Failed to requeue the dead letter"),
        DeadLetterRequeue::AlreadyPending
    );

    assert!(
        storage_ref
            .ask(GetDeadLetterDispatches)
            .await
            .expect("Failed to read the dead letters")
            .is_empty()
    );
    let pending = storage_ref
        .ask(GetPendingCrossZoneDispatches)
        .await
        .expect("Failed to read the pending dispatches");
    assert_eq!(
        pending,
        vec![PendingCrossZoneDispatchRecord {
            message_key: [7; 32],
            transaction: vec![9],
            failed_attempts: 1,
        }],
        "The live record is left untouched, keeping its own bytes and attempt count"
    );
}

/// The one destructive-looking branch: a requeue the cap turns away must leave
/// the dead letter retained, or the refusal destroys the operator's only handle
/// on the message.
#[tokio::test]
async fn a_requeue_refused_by_the_pending_cap_keeps_the_dead_letter() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    retire_dispatch(&storage_ref, [7; 32], 7).await;
    let full: Vec<_> = (0..MAX_PENDING_CROSS_ZONE_DISPATCHES)
        .map(|index| PendingCrossZoneDispatchRecord::recorded(key_from_index(index), vec![0; 4]))
        .collect();
    storage_ref
        .ask(AddPendingCrossZoneDispatches { dispatches: full })
        .await
        .expect("Failed to fill the pending list");

    storage_ref
        .ask(RequeueDeadLetterDispatch {
            message_key: [7; 32],
        })
        .await
        .expect_err("A full pending list refuses the requeue");

    let dead_letters = storage_ref
        .ask(GetDeadLetterDispatches)
        .await
        .expect("Failed to read the dead letters");
    assert_eq!(dead_letters.len(), 1);
    assert_eq!(dead_letters[0].message_key, [7; 32]);
    assert_eq!(
        pending_dispatch_keys(&storage_ref).await.len(),
        MAX_PENDING_CROSS_ZONE_DISPATCHES,
        "The refused requeue must not touch the pending list"
    );
}

/// An oversized delivery is still listed and counted, but its bytes are not
/// retained, and a requeue says so instead of restoring an empty transaction.
#[tokio::test]
async fn an_oversized_dead_letter_is_listed_but_not_requeueable() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    retire_dispatch_carrying(
        &storage_ref,
        [7; 32],
        7,
        vec![0; DeadLetterDispatch::MAX_RETAINED_TRANSACTION_BYTES + 1],
    )
    .await;

    let dead_letters = storage_ref
        .ask(GetDeadLetterDispatches)
        .await
        .expect("Failed to read the dead letters");
    assert_eq!(dead_letters.len(), 1);
    assert!(
        dead_letters[0].transaction.is_empty(),
        "Bytes over the retention bound are not kept"
    );

    assert_eq!(
        storage_ref
            .ask(RequeueDeadLetterDispatch {
                message_key: [7; 32]
            })
            .await
            .expect("Failed to requeue the dead letter"),
        DeadLetterRequeue::NotRetained
    );
    assert_eq!(
        storage_ref
            .ask(GetDeadLetterDispatches)
            .await
            .expect("Failed to read the dead letters")
            .len(),
        1,
        "The record stays listed for the operator to trace"
    );
    assert!(pending_dispatch_keys(&storage_ref).await.is_empty());
}
