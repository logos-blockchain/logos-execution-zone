use std::{collections::HashSet, path::Path, sync::Arc};

use common::{
    HashType,
    block::{BedrockStatus, Block, BlockMeta},
    test_utils::{
        produce_dummy_block, produce_dummy_block_with_reverted, produce_dummy_empty_transaction,
    },
    transaction::{TxEvents, clock_invocation},
};
use kameo::actor::{ActorRef, Spawn as _};
use lee::{Account, AccountId, V03State};
use lee_core::program::{ProgramEvent, TransactionEvent};

use crate::{
    StorageActor,
    protocol::{
        AtomicUpdate, GetAccountTransactions, GetBlock, GetBlockByHash, GetBlockEvents,
        GetChannelViewBytes, GetFinalSnapshot, GetFirstBlockId, GetLastBlockId, GetLatestBlockMeta,
        GetLeeState, GetPendingDepositEvents, GetTransactionByHash, GetTransactionReceiptByHash,
        GetZoneCheckpoint, PendingDepositEventRecord, UpdateZoneCheckpoint,
        WithdrawalReconciliationKey,
    },
};
/// An update that touches no block, for filling in one bookkeeping field.
fn bookkeeping_update() -> AtomicUpdate {
    AtomicUpdate {
        blocks: Vec::new(),
        head_tip: None,
        head_state: Arc::new(V03State::new()),
        final_snapshot: None,
        finalized_up_to: None,
        new_deposit_events: Vec::new(),
        finalized_deposit_records: HashSet::new(),
        consumed_withdrawals: HashSet::new(),
        new_withdraw_intents: HashSet::new(),
        zone_anchor: None,
        events: Vec::new(),
        channel_view: None,
    }
}

/// The checkpoint bytes the store holds, or [`None`] when it holds none.
async fn stored_checkpoint(storage_ref: &ActorRef<StorageActor>) -> Option<Vec<u8>> {
    storage_ref
        .ask(GetZoneCheckpoint)
        .await
        .expect("Failed to read the checkpoint")
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
        ..AtomicUpdate::from_block(head_tip.clone(), Arc::new(V03State::new()), Vec::new())
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
            .ask(AtomicUpdate::from_block(
                block,
                Arc::new(V03State::new()),
                Vec::new(),
            ))
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
    Arc::new(V03State::new().with_public_accounts([(marker_id(), Account::funded(balance))]))
}

/// The balance of the marker account in the stored head state.
async fn stored_balance(storage_ref: &ActorRef<StorageActor>) -> u128 {
    storage_ref
        .ask(GetLeeState)
        .await
        .expect("Failed to read the stored state")
        .expect("The store holds a chain")
        .get_account_by_id(marker_id())
        .data
        .native_balance()
        .expect("The marker balance is canonical")
}

/// The stored block at `block_id`, which has to be there.
async fn stored_block(storage_ref: &ActorRef<StorageActor>, block_id: u64) -> Block {
    storage_ref
        .ask(GetBlock { block_id })
        .await
        .expect("Failed to read the block")
        .expect("The block is stored")
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
        .ask(AtomicUpdate::from_block(
            block,
            Arc::new(V03State::new()),
            Vec::new(),
        ))
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

#[tokio::test]
async fn recorded_transaction_receipt_is_looked_up_by_hash() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let transaction = produce_dummy_empty_transaction();
    let block = produce_dummy_block_with_reverted(1, None, vec![transaction.clone()], &[0]);
    let clock_hash = block
        .body
        .transactions
        .last()
        .expect("has a clock tx")
        .hash();
    let storage_ref =
        spawn_with_blocks(dir.path(), vec![produce_dummy_block(0, None, vec![])]).await;
    storage_ref
        .ask(AtomicUpdate::from_block(
            block.clone(),
            Arc::new(V03State::new()),
            Vec::new(),
        ))
        .await
        .expect("Failed to record the block");

    assert_eq!(
        storage_ref
            .ask(GetTransactionReceiptByHash {
                hash: transaction.hash()
            })
            .await
            .expect("Failed to look the receipt up"),
        Some(block.body.receipts[0]),
    );
    assert!(!block.body.receipts[0].success);
    assert_eq!(
        storage_ref
            .ask(GetTransactionReceiptByHash { hash: clock_hash })
            .await
            .expect("Failed to look the receipt up"),
        None,
        "the clock transaction has no receipt",
    );
}

#[tokio::test]
async fn recorded_events_is_looked_up_by_block_id() {
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

    let block_id = block.header.block_id;

    storage_ref
        .ask(AtomicUpdate::from_block(
            block,
            Arc::new(V03State::new()),
            vec![(
                block_id,
                vec![TxEvents {
                    tx_index: 0,
                    tx_hash: HashType([42; 32]),
                    events: vec![TransactionEvent {
                        account_id: AccountId::new([43; 32]),
                        event: ProgramEvent {
                            selector: [1; 8],
                            data: vec![1; 4],
                        },
                    }],
                }],
            )],
        ))
        .await
        .expect("Failed to record the block");

    let block_events = storage_ref
        .ask(GetBlockEvents { block_id })
        .await
        .expect("Failed to look the events up")
        .expect("There should be one event");

    assert_eq!(block_events[0].events[0].event.data, vec![1; 4]);
    assert_eq!(block_events[0].events[0].event.selector, [1; 8]);
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
        .ask(AtomicUpdate::from_block(
            adopted,
            Arc::new(V03State::new()),
            Vec::new(),
        ))
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

#[tokio::test]
async fn net_shortening_reorg_drops_block_maps() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let genesis = produce_dummy_block(0, None, vec![]);
    let block1a = produce_dummy_block(1, Some(genesis.header.hash), vec![]);
    let block2 = produce_dummy_block(2, Some(block1a.header.hash), vec![]);
    let block1b = produce_dummy_block(1, Some(HashType([9; 32])), vec![]);

    let storage_ref = spawn_with_blocks(
        dir.path(),
        vec![genesis.clone(), block1a.clone(), block2.clone()],
    )
    .await;

    assert_eq!(
        storage_ref
            .ask(GetBlockByHash {
                block_hash: genesis.header.hash
            })
            .await
            .expect("Failed to read map for block 0")
            .expect("Block 0 is stored"),
        0
    );

    assert_eq!(
        storage_ref
            .ask(GetBlockByHash {
                block_hash: block1a.header.hash
            })
            .await
            .expect("Failed to read map for block 1")
            .expect("Block 1 is stored"),
        1
    );

    assert_eq!(
        storage_ref
            .ask(GetBlockByHash {
                block_hash: block2.header.hash
            })
            .await
            .expect("Failed to read map for block 2")
            .expect("Block 2 is stored"),
        2
    );

    storage_ref
        .ask(reorg_update(vec![block1b.clone()], &block1b))
        .await
        .expect("Failed to apply the reorg");

    assert_eq!(
        storage_ref
            .ask(GetBlockByHash {
                block_hash: genesis.header.hash
            })
            .await
            .expect("Failed to read map for block 0")
            .expect("Block 0 is stored"),
        0
    );

    assert_eq!(
        storage_ref
            .ask(GetBlockByHash {
                block_hash: block1b.header.hash
            })
            .await
            .expect("Failed to read map for block 1")
            .expect("Block 1 is stored"),
        1
    );

    assert_eq!(
        storage_ref
            .ask(GetBlockByHash {
                block_hash: block2.header.hash
            })
            .await
            .expect("Failed to read map for block 2"),
        None
    );
}

#[tokio::test]
async fn net_shortening_reorg_drops_acc_maps() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let genesis = produce_dummy_block(0, None, vec![]);
    let block1a = produce_dummy_block(1, Some(genesis.header.hash), vec![]);
    let block2 = produce_dummy_block(2, Some(block1a.header.hash), vec![]);
    let block1b = produce_dummy_block(1, Some(HashType([9; 32])), vec![]);

    let storage_ref = spawn_with_blocks(
        dir.path(),
        vec![genesis.clone(), block1a.clone(), block2.clone()],
    )
    .await;

    let genesis_clock_tx = clock_invocation(0, 0_u64.saturating_mul(100));
    let block_1a_clock_tx = clock_invocation(1, 1_u64.saturating_mul(100));
    let block_2_clock_tx = clock_invocation(2, 2_u64.saturating_mul(100));
    let block_1b_clock_tx = clock_invocation(1, 1_u64.saturating_mul(100));

    let clock_acc = genesis_clock_tx.message.execution.root.to.account_id;

    assert_eq!(
        storage_ref
            .ask(GetAccountTransactions {
                account_id: clock_acc,
                offset: 0,
                limit: 3,
            })
            .await
            .expect("Failed to get block id by map"),
        Some(vec![
            genesis_clock_tx.clone().into(),
            block_1a_clock_tx.clone().into(),
            block_2_clock_tx.clone().into(),
        ])
    );

    storage_ref
        .ask(reorg_update(vec![block1b.clone()], &block1b))
        .await
        .expect("Failed to apply the reorg");

    assert_eq!(
        storage_ref
            .ask(GetAccountTransactions {
                account_id: clock_acc,
                offset: 0,
                limit: 3,
            })
            .await
            .expect("Failed to get block id by map"),
        Some(vec![
            genesis_clock_tx.clone().into(),
            block_1b_clock_tx.clone().into(),
        ])
    );
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
            Vec::new(),
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
            ..AtomicUpdate::from_block(block3.clone(), state_with_balance(300), Vec::new())
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
            ..AtomicUpdate::from_block(block2.clone(), state_with_balance(200), Vec::new())
        })
        .await
        .expect("Failed to finalize the block");

    storage_ref
        .ask(AtomicUpdate::from_block(
            block2,
            state_with_balance(300),
            Vec::new(),
        ))
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

/// An update that moves no chain must not pay for a whole state serialization.
#[tokio::test]
async fn an_update_on_the_stored_tip_does_not_rewrite_the_head_state() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), Vec::new()).await;

    let genesis = produce_dummy_block(1, None, vec![]);
    storage_ref
        .ask(AtomicUpdate::from_block(
            genesis.clone(),
            state_with_balance(200),
            Vec::new(),
        ))
        .await
        .expect("Failed to record the genesis block");

    // The chain stands still: the tip is the block already stored, and no block
    // comes with the update. The state it carries is ignored.
    storage_ref
        .ask(AtomicUpdate {
            head_tip: Some(BlockMeta::from(&genesis)),
            head_state: state_with_balance(999),
            ..bookkeeping_update()
        })
        .await
        .expect("Failed to apply the update");

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
            ..AtomicUpdate::from_block(block2.clone(), state_with_balance(300), Vec::new())
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
    assert_eq!(
        final_state
            .get_account_by_id(marker_id())
            .data
            .native_balance()
            .unwrap(),
        200
    );
    assert_eq!(stored_balance(&storage_ref).await, 300);
}

#[tokio::test]
async fn a_stored_checkpoint_is_replaced_by_the_next() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    for bytes in [b"cp-first", b"cp-later"] {
        storage_ref
            .ask(UpdateZoneCheckpoint {
                bytes: bytes.to_vec(),
            })
            .await
            .expect("Failed to store the checkpoint");
    }

    assert_eq!(
        stored_checkpoint(&storage_ref).await.as_deref(),
        Some(b"cp-later".as_slice())
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
    assert!(
        storage_ref
            .ask(GetBlockByHash {
                block_hash: [0; 32].into()
            })
            .await
            .expect("Failed to get block id by map")
            .is_none()
    );
    assert!(
        storage_ref
            .ask(GetBlockEvents { block_id: 1 })
            .await
            .expect("Failed to get events for block id")
            .is_none()
    );
}

/// The property that lets a genesis go in as an ordinary block write.
#[tokio::test]
async fn the_first_block_written_starts_the_chain() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let genesis = produce_dummy_block(1, None, vec![]);
    let storage_ref = spawn_with_blocks(dir.path(), vec![genesis.clone()]).await;

    let block_1_clock_tx = clock_invocation(1, 1_u64.saturating_mul(100));
    let block_2_clock_tx = clock_invocation(2, 2_u64.saturating_mul(100));

    let clock_acc = block_1_clock_tx.message.execution.root.to.account_id;

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
    assert_eq!(
        storage_ref
            .ask(GetBlockByHash {
                block_hash: genesis.header.hash
            })
            .await
            .expect("Failed to get block id by map"),
        Some(1)
    );
    assert_eq!(
        storage_ref
            .ask(GetAccountTransactions {
                account_id: clock_acc,
                offset: 0,
                limit: 100,
            })
            .await
            .expect("Failed to get block id by map"),
        Some(vec![block_1_clock_tx.clone().into()])
    );

    // A later block extends the chain rather than restarting it.
    let second = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let second_hash = second.header.hash;
    storage_ref
        .ask(AtomicUpdate::from_block(
            second,
            Arc::new(V03State::new()),
            Vec::new(),
        ))
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
    assert_eq!(
        storage_ref
            .ask(GetBlockByHash {
                block_hash: second_hash
            })
            .await
            .expect("Failed to get block id by map"),
        Some(2)
    );
    assert_eq!(
        storage_ref
            .ask(GetAccountTransactions {
                account_id: clock_acc,
                offset: 0,
                limit: 100,
            })
            .await
            .expect("Failed to get block id by map"),
        Some(vec![block_1_clock_tx.into(), block_2_clock_tx.into()])
    );
}

#[tokio::test]
async fn acc_id_to_tx_map_corectness() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let genesis = produce_dummy_block(1, None, vec![]);
    let storage_ref = spawn_with_blocks(dir.path(), vec![genesis.clone()]).await;

    let block_1_clock_tx = clock_invocation(1, 1_u64.saturating_mul(100));
    let block_2_clock_tx = clock_invocation(2, 2_u64.saturating_mul(100));
    let block_3_clock_tx = clock_invocation(3, 3_u64.saturating_mul(100));
    let block_4_clock_tx = clock_invocation(4, 4_u64.saturating_mul(100));

    let clock_acc = block_1_clock_tx.message.execution.root.to.account_id;

    // A later block extends the chain rather than restarting it.
    let block_2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let block_2_hash = block_2.header.hash;

    storage_ref
        .ask(AtomicUpdate::from_block(
            block_2,
            Arc::new(V03State::new()),
            Vec::new(),
        ))
        .await
        .expect("Failed to record the second block");

    let block_3 = produce_dummy_block(3, Some(block_2_hash), vec![]);
    let block_3_hash = block_3.header.hash;

    storage_ref
        .ask(AtomicUpdate::from_block(
            block_3,
            Arc::new(V03State::new()),
            Vec::new(),
        ))
        .await
        .expect("Failed to record the second block");

    let block_4 = produce_dummy_block(4, Some(block_3_hash), vec![]);

    storage_ref
        .ask(AtomicUpdate::from_block(
            block_4,
            Arc::new(V03State::new()),
            Vec::new(),
        ))
        .await
        .expect("Failed to record the second block");

    assert_eq!(
        storage_ref
            .ask(GetAccountTransactions {
                account_id: clock_acc,
                offset: 0,
                limit: 2,
            })
            .await
            .expect("Failed to get block id by map"),
        Some(vec![
            block_1_clock_tx.clone().into(),
            block_2_clock_tx.clone().into()
        ])
    );

    assert_eq!(
        storage_ref
            .ask(GetAccountTransactions {
                account_id: clock_acc,
                offset: 1,
                limit: 2,
            })
            .await
            .expect("Failed to get block id by map"),
        Some(vec![
            block_2_clock_tx.clone().into(),
            block_3_clock_tx.clone().into()
        ])
    );

    assert_eq!(
        storage_ref
            .ask(GetAccountTransactions {
                account_id: clock_acc,
                offset: 1,
                limit: 3,
            })
            .await
            .expect("Failed to get block id by map"),
        Some(vec![
            block_2_clock_tx.into(),
            block_3_clock_tx.into(),
            block_4_clock_tx.into()
        ])
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

/// The view has to outlive the process: a restart without it has no head to
/// build on and nothing to chain the next publish onto.
#[tokio::test]
async fn channel_view_survives_a_reopen() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn_with_blocks(dir.path(), vec![]).await;

    assert_eq!(
        storage_ref
            .ask(GetChannelViewBytes)
            .await
            .expect("Failed to read the channel view"),
        None,
        "A store written without a view has none to report"
    );

    storage_ref
        .ask(AtomicUpdate {
            channel_view: Some(vec![7; 3]),
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
            .ask(GetChannelViewBytes)
            .await
            .expect("Failed to read the channel view"),
        Some(vec![7; 3]),
        "The view comes back after a restart, and an update carrying none left it alone"
    );
}

#[test]
fn opening_fails_when_the_db_path_is_a_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("db");
    // Force RocksDB open to fail with an IO error by placing a file at DB path.
    std::fs::write(&db_path, b"not-a-directory").unwrap();

    assert!(StorageActor::new(&db_path).is_err());
}
