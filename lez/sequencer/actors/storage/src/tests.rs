use std::{path::Path, sync::Arc};

use common::{
    HashType,
    block::{Block, BlockMeta},
    test_utils::{produce_dummy_block, produce_dummy_empty_transaction},
};
use kameo::actor::{ActorRef, Spawn as _};
use lee::V03State;

use crate::{
    StorageActor,
    protocol::{ApplyStoreUpdate, GetTransactionByHash, RecordNewBlock},
};

/// Spawns an actor on a database at `path` seeded with `blocks`.
async fn spawn_with_blocks(path: &Path, blocks: Vec<Block>) -> ActorRef<StorageActor> {
    let storage_ref = StorageActor::spawn(StorageActor::new(path).expect("Failed to open db"));
    for block in blocks {
        storage_ref
            .ask(RecordNewBlock {
                block,
                withdrawals: vec![],
                state: Arc::new(V03State::new()),
                checkpoint_bytes: None,
            })
            .await
            .expect("Failed to record a block");
    }
    storage_ref
}

/// Holding the task's output keeps the stopped actor's state alive, which is exactly the
/// situation `on_stop` exists for: the lock has to be gone by the time the shutdown result
/// resolves, not by the time the state happens to be dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        .ask(RecordNewBlock {
            block,
            withdrawals: vec![],
            state: Arc::new(V03State::new()),
            checkpoint_bytes: None,
        })
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        .ask(ApplyStoreUpdate {
            checkpoint: None,
            blocks: vec![(adopted.clone(), false)],
            head_tip: Some(BlockMeta::from(&adopted)),
            head_state: Arc::new(V03State::new()),
            final_snapshot: None,
            finalized_up_to: None,
            new_deposit_events: vec![],
            remove_deposit_records: vec![],
            remove_dispatch_records: vec![],
            consumed_withdrawals: vec![],
            new_withdraw_intents: vec![],
            zone_anchor: None,
            lower_published_high_water: None,
        })
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
