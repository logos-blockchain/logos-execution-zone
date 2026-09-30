//! Starting the executor: creating the channel, and restarting over a store it already holds.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
};

use anyhow::Result;
use common::{
    block::{Block, BlockMeta},
    transaction::LeeTransaction,
};
use kameo::actor::Spawn as _;
use lee::V03State;
use lee_core::BlockId;
use sequencer_bedrock_actor::{
    mock::{CannedChannel, MockBedrockActor, SharedChannel, checkpoint_at, mock_msg_of},
    protocol::{BlockData, ChannelUpdate, FinalizedBlock, MsgId, Slot},
};
use sequencer_core::{TransactionOrigin, config::SequencerConfig};
use sequencer_storage_actor::{
    mock::MockStorageActor,
    protocol::{
        AtomicUpdate, GetBlock, RaisePublishedHighWater, SetZoneAnchor, SetZoneCheckpointBytes,
        StoreUpdateOutcome, ZoneAnchorRecord,
    },
};
use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};
use tokio::test;

use super::{new_executor, sequencer_config, spawn_bedrock_pool};
use crate::{
    ExecutorActor,
    actor::state::{State, online::OnlineState},
};

type Executor = ExecutorActor<MockStorageActor, MockBedrockActor>;

/// What a mocked store holds.
#[derive(Default)]
struct Stored {
    blocks: BTreeMap<BlockId, Block>,
    head_state: Option<V03State>,
    final_snapshot: Option<(V03State, BlockMeta)>,
    anchor: Option<ZoneAnchorRecord>,
    checkpoint: Option<Vec<u8>>,
    channel_cursor: Option<sequencer_storage_actor::protocol::MsgId>,
    published_high_water: Option<BlockId>,
}

impl Stored {
    fn apply(&mut self, update: AtomicUpdate) {
        for block in update.blocks {
            self.blocks.insert(block.header.block_id, block);
        }
        if let Some(head_tip) = update.head_tip {
            self.blocks.retain(|block_id, _| *block_id <= head_tip.id);
        }
        self.head_state = Some(V03State::clone(&update.head_state));
        if let Some((state, meta)) = update.final_snapshot {
            self.final_snapshot = Some((V03State::clone(&state), meta));
        }
        self.anchor = update.zone_anchor.or(self.anchor);
        if let Some(checkpoint) = update.checkpoint {
            self.checkpoint = Some(checkpoint);
        }
        self.channel_cursor = update.channel_cursor.or(self.channel_cursor);
        if let Some(block_id) = update.lower_published_high_water {
            self.published_high_water = self.published_high_water.map(|mark| mark.min(block_id));
        }
    }

    fn tip(&self) -> Option<BlockMeta> {
        self.blocks.values().next_back().map(BlockMeta::from)
    }
}

/// A [`Stored`] every mock built from it serves, so it survives a restart.
#[derive(Clone, Default)]
struct Store(Arc<Mutex<Stored>>);

impl Store {
    /// A mock serving every read startup and production make, and applying their writes.
    fn mock(&self) -> MockStorageActor {
        let mut mock = MockStorageActor::new();
        mock.expect_handle_get_final_snapshot().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().final_snapshot.clone())
        });
        mock.expect_handle_get_all_blocks().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.blocks())
        });
        mock.expect_handle_get_block().returning({
            let store = self.clone();
            move |GetBlock { block_id }, _ctx| Ok(store.lock().blocks.get(&block_id).cloned())
        });
        mock.expect_handle_get_first_block_id().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().blocks.keys().next().copied())
        });
        mock.expect_handle_get_last_block_id().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().tip().map(|tip| tip.id))
        });
        mock.expect_handle_get_latest_block_meta().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().tip())
        });
        mock.expect_handle_get_lee_state().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().head_state.clone())
        });
        mock.expect_handle_get_channel_cursor().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().channel_cursor)
        });
        mock.expect_handle_get_zone_checkpoint_bytes().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().checkpoint.clone())
        });
        mock.expect_handle_set_zone_checkpoint_bytes().returning({
            let store = self.clone();
            move |SetZoneCheckpointBytes { bytes }, _ctx| {
                store.lock().checkpoint = Some(bytes);
                Ok(())
            }
        });
        mock.expect_handle_get_zone_anchor().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().anchor)
        });
        mock.expect_handle_set_zone_anchor().returning({
            let store = self.clone();
            move |SetZoneAnchor { anchor }, _ctx| {
                store.lock().anchor = Some(anchor);
                Ok(())
            }
        });
        mock.expect_handle_get_published_high_water().returning({
            let store = self.clone();
            move |_msg, _ctx| Ok(store.lock().published_high_water)
        });
        mock.expect_handle_raise_published_high_water().returning({
            let store = self.clone();
            move |RaisePublishedHighWater { block_id }, _ctx| {
                let mut stored = store.lock();
                stored.published_high_water = stored.published_high_water.max(Some(block_id));
                Ok(())
            }
        });
        mock.expect_handle_apply_store_update().returning({
            let store = self.clone();
            move |update, _ctx| {
                store.lock().apply(update);
                Ok(StoreUpdateOutcome::default())
            }
        });
        mock.expect_handle_get_slash_record_bytes()
            .returning(|_msg, _ctx| Ok(None));
        mock.expect_handle_get_pending_deposit_events()
            .returning(|_msg, _ctx| Ok(Vec::new()));
        mock.expect_handle_get_pending_cross_zone_dispatches()
            .returning(|_msg, _ctx| Ok(Vec::new()));
        mock.expect_handle_drop_settled_cross_zone_dispatches()
            .returning(|_msg, _ctx| Ok(()));
        mock.expect_handle_get_dead_letter_dispatches()
            .returning(|_msg, _ctx| Ok(Vec::new()));
        mock
    }

    /// Every stored block, genesis first.
    fn blocks(&self) -> Vec<Block> {
        self.lock().blocks.values().cloned().collect()
    }

    fn lock(&self) -> MutexGuard<'_, Stored> {
        self.0.lock().expect("mock store lock poisoned")
    }
}

/// Starts an executor over `store`, against a Bedrock serving `channel`.
async fn start(config: &SequencerConfig, store: &Store, channel: &SharedChannel) -> Executor {
    let channel = channel.clone();
    new_executor(
        config.clone(),
        MockStorageActor::spawn(store.mock()),
        spawn_bedrock_pool(move |_channel_id| channel.mock()),
    )
    .await
    .expect("Failed to start the executor")
}

fn online(executor: &mut Executor) -> &mut OnlineState<MockStorageActor, MockBedrockActor> {
    executor
        .state
        .online_mut()
        .expect("the executor must be online")
}

/// Delivers `blocks` as the channel finalizing them, the way the Bedrock actor streams them to a
/// bootstrapping executor.
async fn follow_finalized(executor: &mut Executor, blocks: &[Block]) {
    for block in blocks {
        let finalized = FinalizedBlock {
            block: BlockData::Block(block.clone()),
            msg_id: mock_msg_of(block),
            slot: Slot::from(0),
        };
        executor
            .state
            .modify(|state| async move {
                let State::Bootstrapping(bootstrapping) = state else {
                    panic!("only a bootstrapping executor follows finalized blocks");
                };
                bootstrapping
                    .on_finalized_block(finalized)
                    .await
                    .expect("Failed to follow a finalized block")
            })
            .await;
    }
}

/// A follow update carrying nothing, to fill in the fields a test does not
/// exercise via `..empty_channel_update()`.
fn empty_channel_update() -> ChannelUpdate {
    ChannelUpdate {
        checkpoint: checkpoint_at(MsgId::from([0; 32])),
        adopted: Vec::new(),
        orphaned: Vec::new(),
        finalized: Vec::new(),
        deposits: Vec::new(),
        withdrawals: Vec::new(),
        undecodable: Vec::new(),
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

async fn balance(executor: &mut Executor, account: usize) -> u128 {
    let account_id = initial_public_user_accounts()[account].account_id;
    online(executor)
        .sequencer()
        .with_state(|state| state.get_account_by_id(account_id).balance)
        .await
}

fn assert_carries(block: &Block, user_txs: &[LeeTransaction]) {
    assert_eq!(
        &block.body.transactions[..user_txs.len()],
        user_txs,
        "user transactions differ"
    );
}

#[test]
async fn a_fresh_start_creates_the_channel_on_genesis() {
    let (config, _home) = sequencer_config();
    let store = Store::default();
    let mut executor = start(&config, &store, &CannedChannel::empty().share()).await;

    let sequencer = online(&mut executor).sequencer();
    assert_eq!(sequencer.chain_height().await, 1);
    assert_eq!(sequencer.sequencer_config().max_num_tx_in_block, 10);
    assert_eq!(
        balance(&mut executor, 0).await,
        initial_public_user_accounts()[0].balance
    );
    assert_eq!(
        balance(&mut executor, 1).await,
        initial_public_user_accounts()[1].balance
    );
    assert_eq!(
        store
            .blocks()
            .iter()
            .map(|block| block.header.block_id)
            .collect::<Vec<_>>(),
        [1],
        "genesis is stored"
    );
}

#[test]
async fn a_start_over_a_stored_genesis_bootstraps_from_the_channel() {
    let (config, _home) = sequencer_config();
    let bootstrap_sequencer_key = sequencer_stake_core::SequencerKey::new(
        sequencer_core::load_or_create_signing_key(&config.home.join("bedrock_signing_key"))
            .unwrap()
            .public_key()
            .to_bytes(),
    )
    .unwrap();
    let (genesis, genesis_state) = sequencer_genesis::genesis_block_and_state(
        &config.block_signing_key().unwrap(),
        &config
            .genesis_config(Some(bootstrap_sequencer_key))
            .unwrap(),
    );
    let store = Store::default();
    store.lock().apply(AtomicUpdate::from_block(
        genesis.clone(),
        Arc::new(genesis_state),
    ));

    let channel = CannedChannel {
        tip: Some(mock_msg_of(&genesis)),
        ..CannedChannel::empty()
    }
    .share();
    let mut executor = start(&config, &store, &channel).await;
    follow_finalized(&mut executor, &[genesis]).await;

    assert_eq!(online(&mut executor).sequencer().chain_height().await, 1);
}

#[test]
async fn a_restart_restores_the_state_from_storage() {
    let (config, _home) = sequencer_config();
    let store = Store::default();
    let channel = CannedChannel::empty().share();
    let balance_to_move = 13;

    // A block moving `balance_to_move` from account 0 to account 1 is stored before the restart.
    {
        let mut executor = start(&config, &store, &channel).await;
        let tx = transfer(0, balance_to_move);
        let node = online(&mut executor);
        node.mempool_handle()
            .push((TransactionOrigin::User, tx.clone()))
            .await
            .unwrap();
        node.sequencer_mut().run_production_turn().await.unwrap();
        assert_carries(store.blocks().last().unwrap(), &[tx]);
    }

    let mut executor = start(&config, &store, &channel).await;
    follow_finalized(&mut executor, &store.blocks()).await;

    // The recipient gained exactly the transfer; the sender also paid a real fee.
    assert!(
        balance(&mut executor, 0).await
            < initial_public_user_accounts()[0].balance - balance_to_move
    );
    assert_eq!(
        balance(&mut executor, 1).await,
        initial_public_user_accounts()[1].balance + balance_to_move
    );
}

#[test]
async fn a_block_produced_after_a_restart_chains_on_the_stored_tip() {
    let (config, _home) = sequencer_config();
    let store = Store::default();
    let channel = CannedChannel::empty().share();

    {
        let mut executor = start(&config, &store, &channel).await;
        let node = online(&mut executor);
        node.mempool_handle()
            .push((TransactionOrigin::User, transfer(0, 100)))
            .await
            .unwrap();
        node.sequencer_mut().run_production_turn().await.unwrap();
    }
    let expected_prev_meta = store.lock().tip().expect("block 2 is stored");

    let mut executor = start(&config, &store, &channel).await;
    follow_finalized(&mut executor, &store.blocks()).await;

    let tx = transfer(1, 50);
    let node = online(&mut executor);
    node.mempool_handle()
        .push((TransactionOrigin::User, tx.clone()))
        .await
        .unwrap();
    node.sequencer_mut().run_production_turn().await.unwrap();

    let new_block = store.blocks().pop().expect("block 3 is stored");
    assert_eq!(new_block.header.block_id, 3);
    assert_eq!(
        new_block.header.prev_block_hash, expected_prev_meta.hash,
        "the new block must chain on the stored tip"
    );
    assert_carries(&new_block, &[tx]);
}

/// A pin on an entry we published ourselves at startup must still produce,
/// even while the channel read is too old to show it.
#[test]
async fn the_pin_the_genesis_publish_leaves_survives_a_lagging_channel_read() {
    let (config, _home) = sequencer_config();
    // No channel yet, so startup creates it with our genesis.
    let channel = CannedChannel::absent().share();
    let store = Store::default();
    let mut executor = start(&config, &store, &channel).await;
    let sequencer = online(&mut executor).sequencer_mut();

    // The read does not show our genesis yet.
    channel.serve(CannedChannel {
        tip: Some(mock_msg_of(&store.blocks()[0])),
        stale_tip_read: Some(MsgId::from([42_u8; 32])),
        ..CannedChannel::absent()
    });

    assert!(
        sequencer.pin_behind_channel_tip().await.is_none(),
        "a pin on our own genesis inscription must not be read as behind"
    );
    sequencer
        .run_production_turn()
        .await
        .expect("the first turn must produce, pinned on what the genesis publish left");
}

/// The sdk can deliver a checkpoint it built before our publishes, whose tip is
/// root on a channel that did not exist yet. Believing it would rewind the pin
/// onto a channel we have since filled.
#[test]
async fn a_buffered_startup_checkpoint_cannot_rewind_the_pin() {
    let (config, _home) = sequencer_config();
    let mut executor = start(&config, &Store::default(), &CannedChannel::absent().share()).await;
    let sequencer = online(&mut executor).sequencer_mut();

    // Built before our publishes, so it names none of them and its tip is root.
    sequencer
        .on_channel_update(ChannelUpdate {
            checkpoint: checkpoint_at(MsgId::root()),
            ..empty_channel_update()
        })
        .await;

    // The channel refuses a publish chained on anything but our genesis, so a
    // pin rewound onto root would fail the turn.
    sequencer
        .run_production_turn()
        .await
        .expect("the turn after a stale startup checkpoint must still produce");
}

#[test]
async fn a_restart_restores_the_head_tier_and_recovers_from_an_orphan() -> Result<()> {
    let (config, _home) = sequencer_config();
    let store = Store::default();
    let channel = CannedChannel::empty().share();
    let tx = transfer(0, 10);

    // Produce block 2 (a user transfer), then "crash" before it finalizes.
    {
        let mut executor = start(&config, &store, &channel).await;
        let node = online(&mut executor);
        node.mempool_handle()
            .push((TransactionOrigin::User, tx.clone()))
            .await?;
        node.sequencer_mut().run_production_turn().await?;
    }
    let [genesis, block2] =
        <[Block; 2]>::try_from(store.blocks()).expect("genesis and block 2 are stored");

    // Only genesis is on the channel, so block 2 must come back as *head*, not
    // final — the L1 can still orphan it.
    channel.serve(CannedChannel {
        tip: Some(mock_msg_of(&genesis)),
        ..CannedChannel::empty()
    });
    let mut executor = start(&config, &store, &channel).await;
    follow_finalized(&mut executor, std::slice::from_ref(&genesis)).await;
    assert_eq!(online(&mut executor).sequencer().chain_height().await, 2);

    // The L1 orphans block 2 and adopts a competing empty block 2'.
    let block2_prime =
        common::test_utils::produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let block2_prime_msg = mock_msg_of(&block2_prime);
    channel.serve(CannedChannel {
        tip: Some(block2_prime_msg),
        ..CannedChannel::empty()
    });
    let sequencer = online(&mut executor).sequencer_mut();
    sequencer
        .on_channel_update(ChannelUpdate {
            checkpoint: checkpoint_at(block2_prime_msg),
            adopted: vec![block2_prime.clone()],
            orphaned: vec![block2],
            ..empty_channel_update()
        })
        .await;

    // The head reorged onto 2': transfer reverted, store overwritten, and the
    // orphaned user tx returned to the mempool.
    assert_eq!(sequencer.chain_height().await, 2);
    let sender = initial_public_user_accounts()[0].account_id;
    assert_eq!(
        sequencer
            .with_state(|state| state.get_account_by_id(sender).balance)
            .await,
        initial_public_user_accounts()[0].balance,
        "the orphaned transfer must be reverted"
    );
    assert_eq!(
        store.lock().blocks[&2].header.hash,
        block2_prime.header.hash,
        "block 2' replaces block 2 in the store"
    );
    sequencer.run_production_turn().await?;
    let block3 = store.blocks().pop().expect("block 3 is stored");
    assert_eq!(block3.header.prev_block_hash, block2_prime.header.hash);
    assert_carries(&block3, &[tx]);

    Ok(())
}

#[test]
async fn a_restart_reanchors_on_the_persisted_final_snapshot() {
    let (config, _home) = sequencer_config();
    let store = Store::default();
    let channel = CannedChannel::empty().share();

    // Produce block 2 and follow its finalization, which persists the final
    // snapshot; then "crash".
    {
        let mut executor = start(&config, &store, &channel).await;
        let node = online(&mut executor);
        node.mempool_handle()
            .push((
                TransactionOrigin::User,
                common::test_utils::produce_dummy_empty_transaction(),
            ))
            .await
            .unwrap();
        node.sequencer_mut().run_production_turn().await.unwrap();
        let block2 = store.blocks().pop().expect("block 2 is stored");
        node.sequencer_mut()
            .on_channel_update(ChannelUpdate {
                finalized: vec![(block2, Slot::from(0))],
                ..empty_channel_update()
            })
            .await;
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
    let mut executor = start(&config, &store, &channel).await;
    let blocks = store.blocks();
    follow_finalized(&mut executor, &blocks).await;
    let sequencer = online(&mut executor).sequencer_mut();
    sequencer
        .on_channel_update(ChannelUpdate {
            orphaned: vec![blocks[1].clone()],
            ..empty_channel_update()
        })
        .await;

    assert_eq!(sequencer.chain_height().await, 2);
    assert_eq!(
        store.lock().blocks[&2].header.hash,
        blocks[1].header.hash,
        "a finalized block stays stored"
    );
}
