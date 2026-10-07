//! Startup reconstruction: a starting executor replays the finalized channel
//! history its store misses.

use anyhow::Result;
use chain_state::{ChainState, ChannelEntry, Tip};
use common::{
    HashType,
    block::{Block, BlockMeta},
    test_utils::produce_dummy_block,
    transaction::LeeTransaction,
};
use kameo::actor::Spawn as _;
use lee::{
    AccountId, ProgramShardSelector, PublicTransaction, V03State,
    public_transaction::{Message, WitnessSet},
};
use ping_core::{ReceiverInstruction, ping_record_pda, receiver_config_account_id};
use sequencer_bedrock_actor::{
    mock::{CannedChannel, mock_msg_of},
    protocol::{BlockData, ChannelEvent, ChannelEventKind, FinalizedBlock, MsgId, Slot},
};
use sequencer_storage_actor::{
    mock::{CannedStore, MockStorageActor, SharedStore},
    protocol::{PendingCrossZoneDispatchRecord, PendingDepositEventRecord, ZoneAnchorRecord},
};
use tokio::test;

use super::{
    finalized_at, new_executor, sequencer_config, spawn_bedrock_pool,
    stored_chain::{
        PEER_ZONE, block_at, cross_zone_genesis_store, finalized_genesis_store, genesis,
        with_finalized, with_head,
    },
};
use crate::{ExecutorActor, protocol::GetLastBlockId};

fn anchor_at(block: &Block, slot: u64) -> ZoneAnchorRecord {
    ZoneAnchorRecord {
        slot,
        block_id: block.header.block_id,
        hash: block.header.hash,
    }
}

/// Asserts `block`, read off the channel at `slot`, is stored as the final and the head tip, with
/// the anchor on it.
fn assert_reconstructed(store: &SharedStore, block: &Block, slot: u64) {
    let stored = store.lock();
    assert_eq!(
        stored.tip().map(|tip| tip.hash),
        Some(block.header.hash),
        "the block is the head tip"
    );
    assert_eq!(
        stored.final_snapshot.as_ref().map(|(_, meta)| meta.hash),
        Some(block.header.hash),
        "the block is final"
    );
    assert_eq!(stored.anchor, Some(anchor_at(block, slot)));
}

fn stored_hashes(store: &SharedStore) -> Vec<HashType> {
    store
        .blocks()
        .iter()
        .map(|block| block.header.hash)
        .collect()
}

/// Starts an executor over `store` and follows `history`: the finalized channel entries the
/// Bedrock actor streams from the stored anchor on. The last one is the channel tip; an empty
/// history means there is no channel.
async fn start(store: &SharedStore, history: Vec<FinalizedBlock>) -> Result<()> {
    start_observing(store, history, |_store| {}).await
}

/// [`start`], calling `observe` on the store after each entry of `history` replays.
async fn start_observing(
    store: &SharedStore,
    history: Vec<FinalizedBlock>,
    mut observe: impl FnMut(&SharedStore),
) -> Result<()> {
    let (config, _home) = sequencer_config();
    let channel = history
        .last()
        .map_or_else(CannedChannel::absent, |tip| CannedChannel {
            tip_slot: Some(tip.slot),
            tip: Some(tip.msg_id),
            ..CannedChannel::absent()
        })
        .share();
    let channel_id = config.bedrock_config.channel_id;
    let executor = ExecutorActor::spawn(
        Box::pin(new_executor(
            config,
            MockStorageActor::spawn(store.mock()),
            spawn_bedrock_pool(move |_channel_id| channel.mock()),
        ))
        .await?,
    );
    for finalized in history {
        executor
            .ask(ChannelEvent {
                channel_id,
                event: ChannelEventKind::FinalizedBlock(Box::new(finalized)),
            })
            .await?;
        observe(store);
    }
    executor.ask(GetLastBlockId).await?;
    Ok(())
}

fn peer_block_hash(src_block_id: u64) -> [u8; 32] {
    let mut hash = [0_u8; 32];
    hash[..8].copy_from_slice(&src_block_id.to_le_bytes());
    hash
}

/// A delivery of `payload` to the ping receiver, read off peer block `src_block_id`.
fn dispatch_tx(src_block_id: u64, payload: &[u8]) -> LeeTransaction {
    let receiver_id = programs::ping_receiver_account_id();
    let instruction = borsh::to_vec(&ReceiverInstruction::Record {
        payload: payload.to_vec(),
    })
    .expect("ping instruction serializes");
    LeeTransaction::Public(cross_zone::build_dispatch_from_emission(
        &cross_zone::EmissionSource {
            src_zone: PEER_ZONE,
            src_block_id,
            src_block_hash: peer_block_hash(src_block_id),
            src_tx_index: 0,
            src_account_id: programs::ping_sender_account_id(),
        },
        receiver_id,
        &[
            ProgramShardSelector::new(receiver_config_account_id(receiver_id), receiver_id),
            ProgramShardSelector::new(ping_record_pda(receiver_id), receiver_id),
        ],
        instruction,
    ))
}

/// The mint a finalized L1 deposit event injects, as the sequencer builds it.
fn deposit_tx(op_id: [u8; 32], recipient: AccountId, amount: u64) -> LeeTransaction {
    let bridge_program_id = programs::bridge_account_id();
    let message = Message::try_new(
        bridge_program_id,
        vec![
            ProgramShardSelector::native_balance(system_accounts::bridge_account_id()),
            ProgramShardSelector::native_balance(recipient),
            // The receipt PDA carries the exactly-once check, so the program
            // needs it in the account list.
            ProgramShardSelector::new(
                bridge_core::deposit_receipt_account_id(bridge_program_id, op_id),
                bridge_program_id,
            ),
        ],
        Vec::new(),
        bridge_core::Instruction::Deposit {
            l1_deposit_op_id: op_id,
            recipient_id: recipient,
            amount,
        },
    )
    .expect("deposit message builds");
    LeeTransaction::Public(PublicTransaction::new(
        message,
        WitnessSet::from_raw_parts(Vec::new()),
    ))
}

/// Slashing exists because a sequencer can inscribe a non-block payload, and
/// the channel keeps it forever. A replay that treated one as fatal would stop
/// every later node from ever joining.
#[test]
async fn reconstruction_skips_an_undecodable_inscription() -> Result<()> {
    let genesis = genesis();
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let junk = FinalizedBlock {
        block: BlockData::Undecodable(b"not a block".to_vec()),
        msg_id: MsgId::from([0xAA_u8; 32]),
        slot: Slot::from(15),
    };
    let store = finalized_genesis_store().share();

    start(
        &store,
        vec![finalized_at(&genesis, 10), junk, finalized_at(&block2, 20)],
    )
    .await?;

    assert_reconstructed(&store, &block2, 20);
    Ok(())
}

/// The lineage the store's view restores to: its final entry and its held entries.
fn stored_lineage(store: &SharedStore) -> Result<(MsgId, Vec<MsgId>)> {
    let bytes = store
        .lock()
        .channel_view
        .clone()
        .expect("the store holds a view");
    let mut chain = ChainState::from_final(V03State::default(), None);
    chain.restore_view(&bytes)?;
    let held = chain.view().iter().map(|entry| entry.msg).collect();
    Ok((chain.final_msg(), held))
}

/// Genesis, block 2 and block 3, each chained on the one before.
fn three_blocks() -> [Block; 3] {
    let genesis = genesis();
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let block3 = produce_dummy_block(3, Some(block2.header.hash), vec![]);
    [genesis, block2, block3]
}

/// Final through `block2` over its applied state, with `held` on top of it in the head; the
/// stored view, when `final_msg` is given, holds `held` chained on that final entry.
fn final_through(block2: &Block, final_msg: Option<MsgId>, held: &[Block]) -> SharedStore {
    let mut store = with_head(finalized_genesis_store(), block2.clone());
    let final_state = store.head_state.clone().expect("the store holds a chain");
    store.final_snapshot = Some((final_state.clone(), BlockMeta::from(block2)));
    let mut chain = ChainState::from_final(final_state, Some(Tip::from(BlockMeta::from(block2))));
    let mut parent = final_msg.unwrap_or_else(MsgId::root);
    chain.apply_reconstructed(parent, None);
    for block in held {
        store = with_head(store, block.clone());
        chain.apply_extension(vec![ChannelEntry {
            msg: mock_msg_of(block),
            parent,
            block: Some(block.clone()),
        }]);
        parent = mock_msg_of(block);
    }
    if final_msg.is_some() {
        store.channel_view = Some(chain.encode_view());
    }
    store.share()
}

/// A warm start re-reads finalized history the final tier already holds. The
/// lineage must not rewind to those entries, or the first one would drop the
/// held view; it resumes past the stored final entry.
#[test]
async fn a_warm_restart_rereads_history_without_rewinding_the_lineage() -> Result<()> {
    let [genesis, block2, block3] = three_blocks();
    let store = final_through(
        &block2,
        Some(mock_msg_of(&block2)),
        std::slice::from_ref(&block3),
    );

    let mut lineages = Vec::new();
    start_observing(
        &store,
        vec![
            finalized_at(&genesis, 10),
            finalized_at(&block2, 20),
            finalized_at(&block3, 30),
        ],
        |store| lineages.push(stored_lineage(store)),
    )
    .await?;

    let held = (mock_msg_of(&block2), vec![mock_msg_of(&block3)]);
    let lineages = lineages.into_iter().collect::<Result<Vec<_>>>()?;
    assert_eq!(
        lineages,
        [held.clone(), held, (mock_msg_of(&block3), Vec::new())]
    );
    Ok(())
}

/// A final tier stored without its view has a root lineage, so reconstruction
/// rebuilds the lineage from the first message it reads.
#[test]
async fn a_final_tier_without_a_view_rebuilds_the_lineage() -> Result<()> {
    let [genesis, block2, block3] = three_blocks();
    let store = final_through(&block2, None, &[]);

    start(
        &store,
        vec![
            finalized_at(&genesis, 10),
            finalized_at(&block2, 20),
            finalized_at(&block3, 30),
        ],
    )
    .await?;

    assert_eq!(stored_lineage(&store)?, (mock_msg_of(&block3), Vec::new()));
    Ok(())
}

/// A stored final entry without a block still resumes the lineage once re-read.
#[test]
async fn a_blockless_final_entry_resumes_the_lineage() -> Result<()> {
    let [genesis, block2, block3] = three_blocks();
    let junk = MsgId::from([0xAA_u8; 32]);
    let store = final_through(&block2, Some(junk), &[]);

    start(
        &store,
        vec![
            finalized_at(&genesis, 10),
            finalized_at(&block2, 20),
            FinalizedBlock {
                block: BlockData::Undecodable(b"not a block".to_vec()),
                msg_id: junk,
                slot: Slot::from(25),
            },
            finalized_at(&block3, 30),
        ],
    )
    .await?;

    assert_eq!(stored_lineage(&store)?, (mock_msg_of(&block3), Vec::new()));
    Ok(())
}

/// Finalized history that ends before the stored final entry, from a lagging
/// Bedrock node, leaves the lineage and the view as stored.
#[test]
async fn history_short_of_the_final_entry_leaves_the_lineage_alone() -> Result<()> {
    let [genesis, block2, block3] = three_blocks();
    let store = final_through(
        &block2,
        Some(mock_msg_of(&block2)),
        std::slice::from_ref(&block3),
    );

    start(&store, vec![finalized_at(&genesis, 10)]).await?;

    assert_eq!(
        stored_lineage(&store)?,
        (mock_msg_of(&block2), vec![mock_msg_of(&block3)])
    );
    Ok(())
}

#[test]
async fn reconstructs_missing_channel_blocks_into_the_store() -> Result<()> {
    let genesis = genesis();
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let store = finalized_genesis_store().share();

    start(
        &store,
        vec![finalized_at(&genesis, 10), finalized_at(&block2, 20)],
    )
    .await?;
    assert_reconstructed(&store, &block2, 20);

    // Restarting on the reconstructed store applies nothing again; the stream
    // resumes at the anchor.
    start(&store, vec![finalized_at(&block2, 20)]).await?;
    assert_reconstructed(&store, &block2, 20);
    assert_eq!(
        stored_hashes(&store),
        [genesis.header.hash, block2.header.hash]
    );
    Ok(())
}

/// A finalized block whose header hash does not cover its contents is skipped
/// once the final tier holds genesis: it is an offence to slash, not a different
/// chain.
#[test]
async fn reconstruction_skips_a_finalized_block_that_does_not_validate() -> Result<()> {
    let genesis = genesis();
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let mut corrupted = block2.clone();
    corrupted.header.hash = HashType([0xCD_u8; 32]);
    let store = finalized_genesis_store().share();

    start(
        &store,
        vec![finalized_at(&genesis, 10), finalized_at(&corrupted, 20)],
    )
    .await?;

    assert_eq!(stored_hashes(&store), [genesis.header.hash]);
    Ok(())
}

/// The channel carries two inscriptions for one block id — competing sequencers
/// around a turn change — and the final tier already settled that height.
/// Finality is irreversible, so the loser is ignored rather than fatal.
#[test]
async fn reconstruction_ignores_a_duplicate_height_the_final_tier_settled() -> Result<()> {
    let genesis = genesis();
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let competitor = block_at(2, genesis.header.hash, 250);
    assert_ne!(competitor.header.hash, block2.header.hash);
    let store = with_finalized(finalized_genesis_store(), block2.clone()).share();

    start(
        &store,
        vec![
            finalized_at(&genesis, 10),
            finalized_at(&block2, 20),
            finalized_at(&competitor, 999),
        ],
    )
    .await?;

    // The anchor tracks the block we hold, never the one we dropped.
    assert_eq!(
        stored_hashes(&store),
        [genesis.header.hash, block2.header.hash]
    );
    assert_eq!(store.lock().anchor, Some(anchor_at(&block2, 20)));
    Ok(())
}

/// A block the head tier holds is reorg-able by construction, so finalized
/// channel history at that height wins and the head rebases onto it.
#[test]
async fn reconstruction_replaces_a_conflicting_head_block_with_finalized_history() -> Result<()> {
    let genesis = genesis();
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let competitor = block_at(2, genesis.header.hash, 250);
    assert_ne!(competitor.header.hash, block2.header.hash);
    let store = with_head(finalized_genesis_store(), competitor).share();

    start(
        &store,
        vec![finalized_at(&genesis, 10), finalized_at(&block2, 20)],
    )
    .await?;

    assert_reconstructed(&store, &block2, 20);
    Ok(())
}

/// A cross-zone delivery whose record is still pending locally, but whose block
/// arrives already finalized on the channel. Reconstruction must settle the
/// record on the way through: the delivery is permanently reflected in the
/// reconstructed state (the inbox seen shard), so the next production neither
/// re-delivers it nor leaves a record nothing will ever drop.
#[test]
async fn reconstructed_delivery_settles_its_pending_record() -> Result<()> {
    let payload = b"reconstructed";
    let tx = dispatch_tx(23, payload);
    let key = cross_zone_inbox_core::message_key(&PEER_ZONE, 23, 0);
    let record =
        PendingCrossZoneDispatchRecord::recorded(key, borsh::to_vec(&tx).expect("tx encodes"));

    let genesis = genesis();
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![tx]);
    let receiver_id = programs::ping_receiver_account_id();
    let record_id = ping_record_pda(receiver_id);
    let store = CannedStore {
        pending_dispatches: vec![record],
        ..cross_zone_genesis_store()
    }
    .share();

    start(
        &store,
        vec![finalized_at(&genesis, 10), finalized_at(&block2, 20)],
    )
    .await?;

    // The delivery reaches its target program exactly once, and its record goes.
    assert_reconstructed(&store, &block2, 20);
    let stored = store.lock();
    assert_eq!(
        stored
            .head_state
            .as_ref()
            .expect("the head state is stored")
            .get_account_by_id(record_id)
            .data
            .shard(receiver_id)
            .as_ref(),
        payload.as_slice()
    );
    assert!(stored.pending_dispatches.is_empty());
    Ok(())
}

/// A delivery this node published itself, served back by the channel at or below
/// its own tip. That path verifies the block matches and returns early, so it is
/// reached on every restart. It must still settle the delivery's record: the
/// channel serving the block is what makes it irreversible, and nothing later
/// will ever put that key in a block again.
#[test]
async fn a_verified_own_block_settles_its_delivery_records() -> Result<()> {
    let tx = dispatch_tx(37, b"verified");
    let key = cross_zone_inbox_core::message_key(&PEER_ZONE, 37, 0);
    let record =
        PendingCrossZoneDispatchRecord::recorded(key, borsh::to_vec(&tx).expect("tx encodes"));

    let genesis = genesis();
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![tx]);
    let store = CannedStore {
        pending_dispatches: vec![record],
        ..with_finalized(finalized_genesis_store(), block2.clone())
    }
    .share();

    start(
        &store,
        vec![finalized_at(&genesis, 10), finalized_at(&block2, 20)],
    )
    .await?;

    assert_eq!(store.lock().anchor, Some(anchor_at(&block2, 20)));
    assert!(store.lock().pending_dispatches.is_empty());
    Ok(())
}

/// A deposit whose L1 event was observed (a pending record exists) and whose L2
/// mint is already contained in a finalized channel block. Reconstruction must
/// apply the mint exactly once and settle the pending record on the way through,
/// so the next production neither re-mints it nor re-injects it.
#[test]
async fn reconstruction_reconciles_already_finished_deposit() -> Result<()> {
    let recipient = testnet_initial_state::initial_public_user_accounts()[0].account_id;
    let funded = testnet_initial_state::initial_public_user_accounts()[0].balance;
    let deposit_amount = 400_u64;
    let deposit_op_id = [0x1a_u8; 32];
    let bridge_program_id = programs::bridge_account_id();
    let receipt_id = bridge_core::deposit_receipt_account_id(bridge_program_id, deposit_op_id);

    let genesis = genesis();
    let block2 = produce_dummy_block(
        2,
        Some(genesis.header.hash),
        vec![deposit_tx(deposit_op_id, recipient, deposit_amount)],
    );
    let store = CannedStore {
        pending_deposits: vec![PendingDepositEventRecord {
            deposit_op_id: HashType(deposit_op_id),
            source_tx_hash: HashType([0; 32]),
            amount: deposit_amount,
            metadata: Vec::new(),
        }],
        ..finalized_genesis_store()
    }
    .share();

    start(
        &store,
        vec![finalized_at(&genesis, 10), finalized_at(&block2, 20)],
    )
    .await?;

    // The mint lands once and the record its L1 event left behind is dropped.
    assert_reconstructed(&store, &block2, 20);
    let stored = store.lock();
    let head_state = stored
        .head_state
        .as_ref()
        .expect("the head state is stored");
    assert_eq!(
        head_state
            .get_account_by_id(recipient)
            .data
            .native_balance()
            .expect("the recipient holds a native balance"),
        funded + u128::from(deposit_amount)
    );
    assert!(
        !head_state
            .get_account_by_id(receipt_id)
            .data
            .shard(bridge_program_id)
            .is_empty(),
        "the bridge claimed the deposit receipt"
    );
    assert!(stored.pending_deposits.is_empty());
    Ok(())
}

// TODO(withdrawals): the two cases below need bridge withdrawals, which panic
// today (`Withdraws are disabled in the current version of LEZ`), so neither the
// withdraw block nor the L1 event it awaits can be built. Reinstate them when
// withdrawals are enabled; the second also needs whatever replaces the
// unseen-withdraw counter, whose storage API no longer exists.
//
// /// A reconstructed deposit must not be re-minted after cold-start backfill
// /// re-delivers its event: the mint is permanently reflected in the
// /// reconstructed state (the receipt PDA), so the drain has nothing to re-emit.
// /// The withdraw block that follows it must likewise leave no phantom count.
// #[test]
// async fn reconstructed_deposit_is_not_reminted_after_backfill_redelivery() {}
//
// /// A reconstructed withdraw block must not touch the unseen-withdraw counter.
// /// Its finalized L1 Withdraw event was already re-delivered (and dropped as a
// /// no-op) by cold-start backfill, so counting it during reconstruction would
// /// leave a permanent phantom that nothing ever consumes.
// #[test]
// async fn reconstructed_withdraw_leaves_no_phantom_unseen_count() {}
