//! Starting the executor: creating the channel, and restarting over a store it already holds.

use std::sync::Arc;

use anyhow::Result;
use common::{block::Block, transaction::LeeTransaction};
use kameo::actor::{ActorRef, Spawn as _};
use lee_core::BlockId;
use sequencer_bedrock_actor::{
    mock::{CannedChannel, MockBedrockActor, SharedChannel, checkpoint_at, mock_msg_of},
    protocol::{
        ChannelEntry, ChannelEvent, ChannelEventKind, ChannelSeq, ChannelUpdate, MsgId,
        PublisherEvent, Slot, ViewChange,
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
    finalized_at, new_executor, sequencer_config, spawn_bedrock_pool, stored_chain::genesis,
};
use crate::{
    ExecutorActor,
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
    let executor = Box::pin(new_executor(
        config.clone(),
        MockStorageActor::spawn(store.mock()),
        spawn_bedrock_pool(move |_channel_id| channel.mock()),
    ))
    .await?;
    Ok(ExecutorActor::spawn(executor))
}

/// A follow update carrying nothing, to fill in the fields a test does not
/// exercise via `..empty_channel_update()`.
fn empty_channel_update() -> ChannelUpdate {
    ChannelUpdate {
        checkpoint: checkpoint_at(MsgId::from([0; 32])),
        seq: ChannelSeq::mocked(0),
        view: ViewChange::Extension(Vec::new()),
        finalized: Vec::new(),
        deposits: Vec::new(),
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
    }
}

fn transfer(nonce: u128, amount: u128) -> LeeTransaction {
    common::test_utils::create_transaction_native_token_transfer(
        initial_public_user_accounts()[0].account_id,
        nonce,
        initial_public_user_accounts()[1].account_id,
        amount,
        &initial_pub_accounts_private_keys()[0].pub_sign_key,
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
    let executor = start(&config, &store, &CannedChannel::empty().share()).await?;

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
async fn a_start_over_a_stored_genesis_bootstraps_from_the_channel() -> Result<()> {
    let (config, _home) = sequencer_config();
    let bootstrap_sequencer_key = sequencer_stake_core::SequencerKey::new(
        sequencer_core::load_or_create_signing_key(&config.home.join("bedrock_signing_key"))
            .unwrap()
            .public_key()
            .to_bytes(),
    )
    .unwrap();
    let (genesis, genesis_state, genesis_events) = sequencer_genesis::genesis_block_and_state(
        &config.block_signing_key().unwrap(),
        &config
            .genesis_config(Some(bootstrap_sequencer_key))
            .unwrap(),
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
    executor
        .ask(ChannelEvent {
            channel_id: config.bedrock_config.channel_id,
            event: ChannelEventKind::FinalizedBlock(Arc::new(finalized_at(&genesis, 0))),
        })
        .await?;

    assert_eq!(executor.ask(GetLastBlockId).await?, 1);
    Ok(())
}

/// A config change moves the channel tip slot past the slot of the last message, so the tip is
/// reached on that message alone.
#[test]
async fn bootstrapping_reaches_a_tip_whose_slot_a_config_change_moved() -> Result<()> {
    let (config, _home) = sequencer_config();
    let genesis = genesis();
    let channel = CannedChannel {
        tip_slot: Some(Slot::from(50)),
        tip: Some(mock_msg_of(&genesis)),
        ..CannedChannel::absent()
    }
    .share();
    let executor = start(&config, &SharedStore::default(), &channel).await?;

    executor
        .ask(ChannelEvent {
            channel_id: config.bedrock_config.channel_id,
            event: ChannelEventKind::FinalizedBlock(Arc::new(finalized_at(&genesis, 10))),
        })
        .await?;

    assert_eq!(executor.ask(GetLastBlockId).await?, 1);
    Ok(())
}

#[test]
async fn a_restart_restores_the_state_from_storage() -> Result<()> {
    let (config, _home) = sequencer_config();
    let accounts = initial_public_user_accounts();
    let store = SharedStore::default();
    let channel = CannedChannel::empty().share();
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
    for block in store.blocks() {
        executor
            .ask(ChannelEvent {
                channel_id: config.bedrock_config.channel_id,
                event: ChannelEventKind::FinalizedBlock(Arc::new(finalized_at(&block, 0))),
            })
            .await?;
    }

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
    let channel = CannedChannel::empty().share();

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
    for block in store.blocks() {
        executor
            .ask(ChannelEvent {
                channel_id: config.bedrock_config.channel_id,
                event: ChannelEventKind::FinalizedBlock(Arc::new(finalized_at(&block, 0))),
            })
            .await?;
    }

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

/// The sdk can deliver a checkpoint it built before our publishes, whose tip is
/// root on a channel that did not exist yet. Believing it would rewind the pin
/// onto a channel we have since filled.
#[test]
async fn a_buffered_startup_checkpoint_cannot_rewind_the_pin() -> Result<()> {
    let (config, _home) = sequencer_config();
    let store = SharedStore::default();
    let executor = start(&config, &store, &CannedChannel::absent().share()).await?;

    // Built before our publishes, so it names none of them and its tip is root.
    executor
        .ask(ChannelEvent {
            channel_id: config.bedrock_config.channel_id,
            event: ChannelEventKind::Publisher(Arc::new(PublisherEvent::Update(Box::new(
                ChannelUpdate {
                    checkpoint: checkpoint_at(MsgId::root()),
                    ..empty_channel_update()
                },
            )))),
        })
        .await?;
    executor.ask(ProduceBlock).await?;

    // The channel refuses a publish chained on anything but our genesis, so a
    // pin rewound onto root would fail the turn.
    assert_eq!(
        stored_ids(&store),
        [1, 2],
        "the turn after a stale startup checkpoint must still produce"
    );
    Ok(())
}

#[test]
async fn a_restart_restores_the_head_tier_and_recovers_from_an_orphan() -> Result<()> {
    let (config, _home) = sequencer_config();
    let store = SharedStore::default();
    let channel = CannedChannel::empty().share();
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
    executor
        .ask(ChannelEvent {
            channel_id: config.bedrock_config.channel_id,
            event: ChannelEventKind::FinalizedBlock(Arc::new(finalized_at(&genesis, 0))),
        })
        .await?;
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
            event: ChannelEventKind::Publisher(Arc::new(PublisherEvent::Update(Box::new(
                ChannelUpdate {
                    checkpoint: checkpoint_at(block2_prime_msg),
                    view: ViewChange::Conflict {
                        canonical: vec![entry(&block2_prime, &genesis)],
                        orphaned: vec![entry(&block2, &genesis)],
                    },
                    ..empty_channel_update()
                },
            )))),
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
    let channel = CannedChannel::empty().share();

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
                event: ChannelEventKind::Publisher(Arc::new(PublisherEvent::Update(Box::new(
                    ChannelUpdate {
                        finalized: vec![entry(&block2, &store.blocks()[0])],
                        ..empty_channel_update()
                    },
                )))),
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
    for block in &blocks {
        executor
            .ask(ChannelEvent {
                channel_id: config.bedrock_config.channel_id,
                event: ChannelEventKind::FinalizedBlock(Arc::new(finalized_at(block, 0))),
            })
            .await?;
    }
    executor
        .ask(ChannelEvent {
            channel_id: config.bedrock_config.channel_id,
            event: ChannelEventKind::Publisher(Arc::new(PublisherEvent::Update(Box::new(
                ChannelUpdate {
                    view: ViewChange::Conflict {
                        canonical: Vec::new(),
                        orphaned: vec![entry(&blocks[1], &blocks[0])],
                    },
                    ..empty_channel_update()
                },
            )))),
        })
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

/// A bootstrapping executor reports the tip it replays to, and goes on to report itself online.
#[test]
async fn the_status_follows_bootstrapping_to_online() -> Result<()> {
    let (config, _home) = sequencer_config();
    let genesis = genesis();
    let channel = CannedChannel {
        tip: Some(mock_msg_of(&genesis)),
        ..CannedChannel::empty()
    }
    .share();
    let executor = start(&config, &SharedStore::default(), &channel).await?;

    let bootstrapping = executor.ask(GetStatus).await?;
    assert!(
        matches!(
            bootstrapping,
            ExecutorStatus::Bootstrapping {
                target,
                replayed_to: None,
                height: None,
            } if target == mock_msg_of(&genesis)
        ),
        "{bootstrapping:?}"
    );

    executor
        .ask(ChannelEvent {
            channel_id: config.bedrock_config.channel_id,
            event: ChannelEventKind::FinalizedBlock(Arc::new(finalized_at(&genesis, 0))),
        })
        .await?;

    let online = executor.ask(GetStatus).await?;
    assert!(
        matches!(online, ExecutorStatus::Online { height: 1, .. }),
        "{online:?}"
    );
    Ok(())
}
