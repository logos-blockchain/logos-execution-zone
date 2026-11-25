//! Starting the executor: creating the channel, and restarting over a store it already holds.

use std::{collections::BTreeSet, sync::Arc};

use anyhow::Result;
use common::{block::Block, transaction::LeeTransaction};
use kameo::{
    actor::{ActorRef, Spawn as _},
    error::HookError,
};
use lee_core::BlockId;
use logos_blockchain_zone_sdk::core::{
    events::DepositRecreatedNotes,
    mantle::{TxHash, ledger::Inputs, ops::channel::deposit::Metadata},
};
use sequencer_bedrock_actor::{
    mock::{CannedChannel, MockBedrockActor, SharedChannel, mock_msg_of},
    protocol::{
        ChannelEntry, ChannelEvent, ChannelEventKind, ChannelUpdate, DepositInfo, FollowStart,
        MsgId, PendingBlock, PublishOutcome, Slot, ViewChange,
    },
};
use sequencer_core::config::SequencerConfig;
use sequencer_storage_actor::{
    mock::{MockStorageActor, SharedStore},
    protocol::AtomicUpdate,
};
use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};
use tokio::test;

use super::{
    channel_event, executor_args, feed, finalized_at, finalized_updates, ready, sequencer_config,
    spawn_bedrock_pool, spawn_executor, stored_chain::genesis,
};
use crate::{
    ExecutorActor,
    error::Error,
    protocol::{
        ExecutorStatus, GetAccountBalance, GetLastBlockId, GetStatus, ProduceBlock, Transaction,
        TransactionOrigin,
    },
};

type Executor = ExecutorActor<MockStorageActor, MockBedrockActor>;

/// Starts an executor over `store`, against a Bedrock serving `channel`.
async fn start(
    config: &SequencerConfig,
    store: &SharedStore,
    channel: &SharedChannel,
) -> Result<ActorRef<Executor>> {
    let channel = channel.clone();
    Box::pin(spawn_executor(
        config.clone(),
        MockStorageActor::spawn(store.mock()),
        spawn_bedrock_pool(move |_channel_id| channel.mock()),
    ))
    .await
}

/// Replays `blocks` as the channel's finalized history, all at slot 0, and reports it read up to
/// the node's LIB.
async fn replay(
    config: &SequencerConfig,
    executor: &ActorRef<Executor>,
    blocks: &[Block],
) -> Result<()> {
    let channel_id = config.bedrock_config.channel_id;
    feed(
        executor,
        finalized_updates(
            channel_id,
            blocks.iter().map(|block| finalized_at(block, 0)),
        ),
    )
    .await?;
    executor.ask(ready(channel_id)).await?;
    Ok(())
}

/// A follow update carrying nothing, to fill in the fields a test does not
/// exercise via `..empty_channel_update()`.
fn empty_channel_update() -> ChannelUpdate {
    ChannelUpdate {
        lib_slot: Slot::from(0),
        finalized_config: MsgId::root(),
        view: ViewChange::Extension(Vec::new()),
        finalized: Vec::new(),
        deposits: Vec::new(),
        pending_deposits: Vec::new(),
        withdrawals: Vec::new(),
        undecodable: Vec::new(),
        finalized_signers: Vec::new(),
    }
}

/// `block` as the channel entry its publish on `parent` leaves.
fn entry(block: &Block, parent: &Block) -> ChannelEntry {
    ChannelEntry {
        msg: mock_msg_of(block),
        parent: mock_msg_of(parent),
        block: Some(block.clone()),
        finally_absent_keys: BTreeSet::new(),
        final_slot: None,
    }
}

/// A finalized L1 deposit identified by `op_id`.
fn deposit(op_id: [u8; 32]) -> DepositInfo {
    DepositInfo {
        tx_hash: TxHash::from(op_id),
        op_id,
        channel_id: [0; 32].into(),
        inputs: Inputs::empty(),
        notes: DepositRecreatedNotes::default(),
        amount: 5,
        metadata: Metadata::new_unchecked(Vec::new()),
    }
}

fn transfer(nonce: u128, amount: u128) -> LeeTransaction {
    common::test_utils::create_transaction_native_token_transfer(
        initial_public_user_accounts()[0].account_id,
        nonce,
        initial_public_user_accounts()[1].account_id,
        amount,
        &lee::test_utils::TestSigner::from(&initial_pub_accounts_private_keys()[0].secret),
    )
}

fn assert_carries(block: &Block, user_txs: &[LeeTransaction]) {
    assert_eq!(
        &block.body.transactions[..user_txs.len()],
        user_txs,
        "user transactions differ"
    );
}

fn stored_ids(store: &SharedStore) -> Vec<BlockId> {
    store
        .blocks()
        .iter()
        .map(|block| block.header.block_id)
        .collect()
}

#[test]
async fn a_fresh_start_creates_the_channel_on_genesis() -> Result<()> {
    let (config, _home) = sequencer_config();
    let accounts = initial_public_user_accounts();
    let store = SharedStore::default();
    let executor = start(&config, &store, &CannedChannel::absent().share()).await?;

    assert_eq!(executor.ask(GetLastBlockId).await?, 1);
    assert_eq!(
        executor
            .ask(GetAccountBalance {
                account_id: accounts[0].account_id
            })
            .await?,
        accounts[0].balance
    );
    assert_eq!(
        executor
            .ask(GetAccountBalance {
                account_id: accounts[1].account_id
            })
            .await?,
        accounts[1].balance
    );
    assert_eq!(stored_ids(&store), [1], "genesis is stored");
    Ok(())
}

#[test]
async fn creating_a_channel_needs_a_genesis_config() {
    let (config, _home) = sequencer_config();
    let config = SequencerConfig {
        genesis: None,
        ..config
    };
    let channel_id = config.bedrock_config.channel_id;
    let channel = CannedChannel::absent().share();

    let executor = ExecutorActor::spawn(
        Box::pin(executor_args(
            config,
            MockStorageActor::spawn(SharedStore::default().mock()),
            spawn_bedrock_pool(move |_channel_id| channel.mock()),
        ))
        .await,
    );

    let missing_genesis = executor
        .wait_for_startup_with_result(|res| {
            matches!(
                res,
                Err(HookError::Error(Error::MissingGenesisConfig(id))) if id == &channel_id
            )
        })
        .await;
    assert!(
        missing_genesis,
        "a node without a genesis config created the channel"
    );
}

#[test]
async fn an_empty_store_does_not_create_a_channel_that_is_only_configured() {
    let (config, _home) = sequencer_config();
    let channel_id = config.bedrock_config.channel_id;

    let executor = ExecutorActor::spawn(
        Box::pin(executor_args(
            config,
            MockStorageActor::spawn(SharedStore::default().mock()),
            spawn_bedrock_pool(|_channel_id| {
                // Any creation attempt is an unexpected call, failing the start with a panic.
                let mut bedrock = MockBedrockActor::default();
                bedrock
                    .expect_handle_follow_channel()
                    .returning(|_msg, _ctx| {
                        Ok(FollowStart {
                            finalized_config: MsgId::root(),
                            lib_slot: None,
                        })
                    });
                bedrock
                    .expect_handle_get_channel_tip_slot()
                    .returning(|_msg, _ctx| Ok(Some(Slot::from(5))));
                bedrock
                    .expect_handle_get_channel_tip_message_id()
                    .returning(|_msg, _ctx| Ok(Some(MsgId::root())));
                bedrock
            }),
        ))
        .await,
    );

    let without_blocks = executor
        .wait_for_startup_with_result(|res| {
            matches!(
                res,
                Err(HookError::Error(Error::ChannelWithoutBlocks(id))) if id == &channel_id
            )
        })
        .await;
    assert!(
        without_blocks,
        "a node with an empty store tried to create a channel that is already configured"
    );
}

#[test]
async fn a_start_over_a_stored_genesis_bootstraps_from_the_channel() -> Result<()> {
    let (config, _home) = sequencer_config();
    let bootstrap_sequencer_key = sequencer_stake_core::SequencerKey::new(
        sequencer_core::load_or_create_signing_key(
            &config.home.join(sequencer_core::CHANNEL_SIGNING_KEY_FILE),
        )
        .unwrap()
        .public_key()
        .to_bytes(),
    )
    .unwrap();
    let (genesis, genesis_state, genesis_events) = sequencer_genesis::genesis_block_and_state(
        &config.genesis_spec(Some(bootstrap_sequencer_key)).unwrap(),
    );
    let store = SharedStore::default();
    store.lock().apply(AtomicUpdate::from_block(
        genesis.clone(),
        Arc::new(genesis_state),
        vec![(genesis.header.block_id, genesis_events)],
    ));

    let channel = CannedChannel {
        tip: Some(mock_msg_of(&genesis)),
        ..CannedChannel::empty()
    }
    .share();
    let executor = start(&config, &store, &channel).await?;
    let channel_id = config.bedrock_config.channel_id;
    feed(
        &executor,
        finalized_updates(channel_id, [finalized_at(&genesis, 0)]),
    )
    .await?;
    executor.ask(ready(channel_id)).await?;

    assert_eq!(executor.ask(GetLastBlockId).await?, 1);
    Ok(())
}

/// The channel tip at startup can be orphaned and never finalize, so bootstrapping completes once
/// the finalized history is read up to the node's LIB, even with no message there.
#[test]
async fn bootstrapping_completes_once_ready_without_reaching_the_tip() -> Result<()> {
    let (config, _home) = sequencer_config();
    let channel_id = config.bedrock_config.channel_id;
    let genesis = genesis();
    let orphaned = common::test_utils::produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let channel = CannedChannel {
        tip_slot: Some(Slot::from(50)),
        tip: Some(mock_msg_of(&orphaned)),
        ..CannedChannel::absent()
    }
    .share();
    let executor = start(&config, &SharedStore::default(), &channel).await?;

    feed(
        &executor,
        finalized_updates(channel_id, [finalized_at(&genesis, 10)]),
    )
    .await?;
    let bootstrapping = executor.ask(GetStatus).await?;
    assert!(
        matches!(bootstrapping, ExecutorStatus::Bootstrapping { .. }),
        "{bootstrapping:?}"
    );

    executor.ask(ready(channel_id)).await?;
    let online = executor.ask(GetStatus).await?;
    assert!(
        matches!(online, ExecutorStatus::Online { height: 1, .. }),
        "{online:?}"
    );
    assert_eq!(channel.lock().publisher_inits, 1);
    Ok(())
}

/// A node holding no block has nothing to follow the channel from, so it keeps bootstrapping until
/// the channel's first block finalizes.
#[test]
async fn an_empty_chain_bootstraps_until_a_block_finalizes() -> Result<()> {
    let (config, _home) = sequencer_config();
    let channel_id = config.bedrock_config.channel_id;
    let genesis = genesis();
    let channel = CannedChannel {
        tip_slot: Some(Slot::from(5)),
        tip: Some(mock_msg_of(&genesis)),
        ..CannedChannel::absent()
    }
    .share();
    let executor = start(&config, &SharedStore::default(), &channel).await?;

    executor.ask(ready(channel_id)).await?;
    let bootstrapping = executor.ask(GetStatus).await?;
    assert!(
        matches!(bootstrapping, ExecutorStatus::Bootstrapping { .. }),
        "{bootstrapping:?}"
    );

    feed(
        &executor,
        finalized_updates(channel_id, [finalized_at(&genesis, 6)]),
    )
    .await?;
    let online = executor.ask(GetStatus).await?;
    assert!(
        matches!(online, ExecutorStatus::Online { height: 1, .. }),
        "{online:?}"
    );
    Ok(())
}

/// Bootstrapping records the finalized deposits the replayed updates carry.
#[test]
async fn bootstrapping_records_replayed_deposits() -> Result<()> {
    let (config, _home) = sequencer_config();
    let channel_id = config.bedrock_config.channel_id;
    let genesis = genesis();
    let channel = CannedChannel {
        tip_slot: Some(Slot::from(10)),
        tip: Some(mock_msg_of(&genesis)),
        ..CannedChannel::absent()
    }
    .share();
    let store = SharedStore::default();
    let executor = start(&config, &store, &channel).await?;

    for mut update in finalized_updates(channel_id, [finalized_at(&genesis, 10)]) {
        if let ChannelEventKind::Update(channel_update) = &mut update.event {
            channel_update.deposits.push(deposit([1; 32]));
        }
        executor.ask(update).await?;
    }
    assert!(matches!(
        executor.ask(GetStatus).await?,
        ExecutorStatus::Bootstrapping { .. }
    ));

    let recorded: Vec<[u8; 32]> = store
        .lock()
        .pending_deposits
        .iter()
        .map(|record| record.deposit_op_id.0)
        .collect();
    assert_eq!(recorded, [[1; 32]]);
    Ok(())
}

#[test]
async fn a_restart_restores_the_state_from_storage() -> Result<()> {
    let (config, _home) = sequencer_config();
    let accounts = initial_public_user_accounts();
    let store = SharedStore::default();
    let channel = CannedChannel::absent().share();
    let balance_to_move = 13;

    // A block moving `balance_to_move` from account 0 to account 1 is stored before the restart.
    {
        let executor = start(&config, &store, &channel).await?;
        let tx = transfer(0, balance_to_move);
        executor
            .ask(Transaction {
                transaction: tx.clone(),
                origin: TransactionOrigin::User,
            })
            .await?;
        executor.ask(ProduceBlock).await?;
        assert_carries(store.blocks().last().unwrap(), &[tx]);
        executor.stop_gracefully().await?;
        executor.wait_for_shutdown().await;
    }

    let executor = start(&config, &store, &channel).await?;
    replay(&config, &executor, &store.blocks()).await?;

    // The recipient gained exactly the transfer; the sender also paid a real fee.
    assert!(
        executor
            .ask(GetAccountBalance {
                account_id: accounts[0].account_id
            })
            .await?
            < accounts[0].balance - balance_to_move
    );
    assert_eq!(
        executor
            .ask(GetAccountBalance {
                account_id: accounts[1].account_id
            })
            .await?,
        accounts[1].balance + balance_to_move
    );
    Ok(())
}

#[test]
async fn a_block_produced_after_a_restart_chains_on_the_stored_tip() -> Result<()> {
    let (config, _home) = sequencer_config();
    let store = SharedStore::default();
    let channel = CannedChannel::absent().share();

    {
        let executor = start(&config, &store, &channel).await?;
        executor
            .ask(Transaction {
                transaction: transfer(0, 100),
                origin: TransactionOrigin::User,
            })
            .await?;
        executor.ask(ProduceBlock).await?;
        executor.stop_gracefully().await?;
        executor.wait_for_shutdown().await;
    }
    let expected_prev_meta = store.lock().tip().expect("block 2 is stored");

    let executor = start(&config, &store, &channel).await?;
    replay(&config, &executor, &store.blocks()).await?;

    let tx = transfer(1, 50);
    executor
        .ask(Transaction {
            transaction: tx.clone(),
            origin: TransactionOrigin::User,
        })
        .await?;
    executor.ask(ProduceBlock).await?;

    let new_block = store.blocks().pop().expect("block 3 is stored");
    assert_eq!(new_block.header.block_id, 3);
    assert_eq!(
        new_block.header.prev_block_hash, expected_prev_meta.hash,
        "the new block must chain on the stored tip"
    );
    assert_carries(&new_block, &[tx]);
    Ok(())
}

/// A stop after a publish but before its block is stored leaves zone-sdk holding the block as
/// pending, refusing any other block on its parent. A restart must recover the block so production
/// chains on it.
#[test]
async fn a_restart_recovers_a_published_block_the_store_lost() -> Result<()> {
    let (config, _home) = sequencer_config();
    let store = SharedStore::default();
    let channel = CannedChannel::absent().share();
    let recipient = initial_public_user_accounts()[1].clone();
    let balance_to_move = 10;

    let store_before_publish = {
        let executor = start(&config, &store, &channel).await?;
        let store_before_publish = store.lock().clone();
        executor
            .ask(Transaction {
                transaction: transfer(0, balance_to_move),
                origin: TransactionOrigin::User,
            })
            .await?;
        executor.ask(ProduceBlock).await?;
        executor.stop_gracefully().await?;
        executor.wait_for_shutdown().await;
        store_before_publish
    };
    let [genesis, block2] =
        <[Block; 2]>::try_from(store.blocks()).expect("genesis and block 2 are stored");
    *store.lock() = store_before_publish;
    channel.lock().pending_blocks = vec![PendingBlock {
        block: block2.clone(),
        outcome: PublishOutcome {
            this_msg: mock_msg_of(&block2),
            parent: mock_msg_of(&genesis),
            released_notes: Vec::new(),
        },
    }];

    let executor = start(&config, &store, &channel).await?;
    replay(&config, &executor, std::slice::from_ref(&genesis)).await?;
    assert_eq!(stored_ids(&store), [1, 2], "block 2 must be recovered");
    assert_eq!(
        executor
            .ask(GetAccountBalance {
                account_id: recipient.account_id
            })
            .await?,
        recipient.balance + balance_to_move,
        "the recovered block's transfer must apply"
    );

    executor.ask(ProduceBlock).await?;
    let block3 = store.blocks().pop().expect("block 3 is stored");
    assert_eq!(block3.header.block_id, 3);
    assert_eq!(
        block3.header.prev_block_hash, block2.header.hash,
        "block 3 must chain on the recovered block"
    );
    Ok(())
}

#[test]
async fn a_restart_keeps_a_pending_block_the_store_holds() -> Result<()> {
    let (config, _home) = sequencer_config();
    let store = SharedStore::default();
    let channel = CannedChannel::absent().share();

    {
        let executor = start(&config, &store, &channel).await?;
        executor.ask(ProduceBlock).await?;
        executor.stop_gracefully().await?;
        executor.wait_for_shutdown().await;
    }
    let [genesis, block2] =
        <[Block; 2]>::try_from(store.blocks()).expect("genesis and block 2 are stored");
    channel.lock().pending_blocks = vec![PendingBlock {
        block: block2.clone(),
        outcome: PublishOutcome {
            this_msg: mock_msg_of(&block2),
            parent: mock_msg_of(&genesis),
            released_notes: Vec::new(),
        },
    }];

    let executor = start(&config, &store, &channel).await?;
    replay(&config, &executor, std::slice::from_ref(&genesis)).await?;
    executor.ask(ProduceBlock).await?;

    assert_eq!(stored_ids(&store), [1, 2, 3]);
    assert_eq!(
        store.lock().blocks[&3].header.prev_block_hash,
        block2.header.hash,
        "block 3 must chain on the pending block"
    );
    Ok(())
}

/// A pin on an entry we published ourselves at startup must still produce,
/// even while the channel read is too old to show it.
#[test]
async fn the_pin_the_genesis_publish_leaves_survives_a_lagging_channel_read() -> Result<()> {
    let (config, _home) = sequencer_config();
    // No channel yet, so startup creates it with our genesis.
    let channel = CannedChannel::absent().share();
    let store = SharedStore::default();
    let executor = start(&config, &store, &channel).await?;

    // The read does not show our genesis yet.
    channel.serve(CannedChannel {
        tip: Some(mock_msg_of(&store.blocks()[0])),
        stale_tip_read: Some(MsgId::from([42_u8; 32])),
        ..CannedChannel::absent()
    });
    executor.ask(ProduceBlock).await?;

    assert_eq!(
        stored_ids(&store),
        [1, 2],
        "the first turn must produce, pinned on what the genesis publish left"
    );
    Ok(())
}

#[test]
async fn a_restart_restores_the_head_tier_and_recovers_from_an_orphan() -> Result<()> {
    let (config, _home) = sequencer_config();
    let store = SharedStore::default();
    let channel = CannedChannel::absent().share();
    let tx = transfer(0, 10);

    // Produce block 2 (a user transfer), then stop before it finalizes.
    {
        let executor = start(&config, &store, &channel).await?;
        executor
            .ask(Transaction {
                transaction: tx.clone(),
                origin: TransactionOrigin::User,
            })
            .await?;
        executor.ask(ProduceBlock).await?;
        executor.stop_gracefully().await?;
        executor.wait_for_shutdown().await;
    }
    let [genesis, block2] =
        <[Block; 2]>::try_from(store.blocks()).expect("genesis and block 2 are stored");

    // Only genesis is on the channel, so block 2 must come back as *head*, not
    // final — the L1 can still orphan it.
    channel.serve(CannedChannel {
        tip: Some(mock_msg_of(&genesis)),
        ..CannedChannel::empty()
    });
    let executor = start(&config, &store, &channel).await?;
    replay(&config, &executor, std::slice::from_ref(&genesis)).await?;
    assert_eq!(executor.ask(GetLastBlockId).await?, 2);

    // The L1 orphans block 2 and adopts a competing empty block 2'.
    let block2_prime =
        common::test_utils::produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let block2_prime_msg = mock_msg_of(&block2_prime);
    channel.serve(CannedChannel {
        tip: Some(block2_prime_msg),
        ..CannedChannel::empty()
    });
    executor
        .ask(ChannelEvent {
            channel_id: config.bedrock_config.channel_id,
            event: ChannelEventKind::Update(Box::new(ChannelUpdate {
                view: ViewChange::Conflict {
                    canonical: vec![entry(&block2_prime, &genesis)],
                    orphaned: vec![entry(&block2, &genesis)],
                },
                ..empty_channel_update()
            })),
        })
        .await?;

    // The head reorged onto 2': transfer reverted, store overwritten, and the
    // orphaned user tx returned to the mempool.
    assert_eq!(executor.ask(GetLastBlockId).await?, 2);
    assert_eq!(
        executor
            .ask(GetAccountBalance {
                account_id: initial_public_user_accounts()[0].account_id
            })
            .await?,
        initial_public_user_accounts()[0].balance,
        "the orphaned transfer must be reverted"
    );
    assert_eq!(
        store.lock().blocks[&2].header.hash,
        block2_prime.header.hash,
        "block 2' replaces block 2 in the store"
    );
    executor.ask(ProduceBlock).await?;
    let block3 = store.blocks().pop().expect("block 3 is stored");
    assert_eq!(block3.header.prev_block_hash, block2_prime.header.hash);
    assert_carries(&block3, &[tx]);

    Ok(())
}

#[test]
async fn a_restart_reanchors_on_the_persisted_final_snapshot() -> Result<()> {
    let (config, _home) = sequencer_config();
    let store = SharedStore::default();
    let channel = CannedChannel::absent().share();

    // Produce block 2 and follow its finalization, which persists the final
    // snapshot; then stop.
    {
        let executor = start(&config, &store, &channel).await?;
        executor
            .ask(Transaction {
                transaction: transfer(0, 10),
                origin: TransactionOrigin::User,
            })
            .await?;
        executor.ask(ProduceBlock).await?;
        let block2 = store.blocks().pop().expect("block 2 is stored");
        executor
            .ask(ChannelEvent {
                channel_id: config.bedrock_config.channel_id,
                event: ChannelEventKind::Update(Box::new(ChannelUpdate {
                    finalized: vec![entry(&block2, &store.blocks()[0])],
                    ..empty_channel_update()
                })),
            })
            .await?;
        executor.stop_gracefully().await?;
        executor.wait_for_shutdown().await;
    }
    assert_eq!(
        store
            .lock()
            .final_snapshot
            .as_ref()
            .map(|(_, meta)| meta.id),
        Some(2),
        "block 2's finalization is persisted"
    );

    // Restart: the final tier re-anchors on the snapshot, so block 2 is final
    // and an orphan report can no longer revert it.
    let executor = start(&config, &store, &channel).await?;
    let blocks = store.blocks();
    replay(&config, &executor, &blocks).await?;
    executor
        .ask(channel_event(
            config.bedrock_config.channel_id,
            ChannelEventKind::Update(Box::new(ChannelUpdate {
                view: ViewChange::Conflict {
                    canonical: Vec::new(),
                    orphaned: vec![entry(&blocks[1], &blocks[0])],
                },
                ..empty_channel_update()
            })),
        ))
        .await?;

    assert_eq!(executor.ask(GetLastBlockId).await?, 2);
    assert_eq!(
        store.lock().blocks[&2].header.hash,
        blocks[1].header.hash,
        "a finalized block stays stored"
    );
    Ok(())
}

/// The scheduler ticks from startup on, so a turn while bootstrapping is skipped rather than
/// stopping the actor.
#[test]
async fn a_production_turn_while_bootstrapping_does_not_stop_the_actor() -> Result<()> {
    let (config, _home) = sequencer_config();
    let store = SharedStore::default();
    let channel = CannedChannel {
        tip: Some(MsgId::from([7_u8; 32])),
        ..CannedChannel::empty()
    }
    .share();
    let executor = start(&config, &store, &channel).await?;

    executor.ask(ProduceBlock).await?;

    assert!(executor.is_alive(), "the actor must survive the turn");
    assert!(stored_ids(&store).is_empty(), "nothing is produced");
    Ok(())
}

/// A node that is not ready yet fails the first channel read, which must not fail the start.
#[test]
async fn a_failed_channel_read_at_startup_is_retried() -> Result<()> {
    let (config, _home) = sequencer_config();
    let genesis = genesis();
    let channel = CannedChannel {
        tip: Some(mock_msg_of(&genesis)),
        failed_tip_slot_reads: 1,
        ..CannedChannel::empty()
    }
    .share();

    let executor = start(&config, &SharedStore::default(), &channel).await?;

    let status = executor.ask(GetStatus).await?;
    assert!(
        matches!(status, ExecutorStatus::Bootstrapping { .. }),
        "{status:?}"
    );
    assert_eq!(channel.lock().failed_tip_slot_reads, 0);
    Ok(())
}

/// A bootstrapping executor reports the slot it replays up to and the one it completes at, and
/// goes on to report itself online.
#[test]
async fn the_status_follows_bootstrapping_to_online() -> Result<()> {
    let (config, _home) = sequencer_config();
    let channel_id = config.bedrock_config.channel_id;
    let genesis = genesis();
    let channel = CannedChannel {
        tip: Some(mock_msg_of(&genesis)),
        lib_slot: Some(Slot::from(5)),
        ..CannedChannel::empty()
    }
    .share();
    let executor = start(&config, &SharedStore::default(), &channel).await?;

    let bootstrapping = executor.ask(GetStatus).await?;
    assert!(
        matches!(
            bootstrapping,
            ExecutorStatus::Bootstrapping {
                target: Some(target),
                replayed_up_to: None,
                height: None,
            } if target == Slot::from(5)
        ),
        "{bootstrapping:?}"
    );

    feed(
        &executor,
        finalized_updates(channel_id, [finalized_at(&genesis, 0)]),
    )
    .await?;
    let catching = executor.ask(GetStatus).await?;
    assert!(
        matches!(
            catching,
            ExecutorStatus::Bootstrapping {
                target: Some(target),
                replayed_up_to: Some(replayed_up_to),
                height: Some(1),
            } if target == Slot::from(5) && replayed_up_to == Slot::from(0)
        ),
        "{catching:?}"
    );

    executor.ask(ready(channel_id)).await?;

    let online = executor.ask(GetStatus).await?;
    assert!(
        matches!(online, ExecutorStatus::Online { height: 1, .. }),
        "{online:?}"
    );
    Ok(())
}
