//! Startup reconstruction: a starting executor replays the finalized channel
//! history its store misses.

use std::collections::{BTreeMap, BTreeSet};

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
    AccountId, Actor, PublicTransaction, V03State,
    public_transaction::{Message, WitnessSet},
};
use sequencer_bedrock_actor::{
    mock::{CannedChannel, mock_msg_of},
    protocol::{Ed25519Key, Ed25519PublicKey, MsgId, Slot},
};
use sequencer_storage_actor::{
    mock::{CannedStore, MockStorageActor, SharedStore},
    protocol::{PendingDepositEventRecord, ZoneAnchorRecord},
};
use tokio::test;

use super::{
    Finalized, finalized_at, finalized_updates, junk_at, ready, sequencer_config,
    spawn_bedrock_pool, spawn_executor,
    stored_chain::{block_at, finalized_genesis_store, genesis, with_finalized, with_head},
};
use crate::protocol::GetLastBlockId;

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
/// Bedrock actor reports from the stored checkpoint on. The last one is the channel tip; an empty
/// history means there is no channel.
async fn start(store: &SharedStore, history: Vec<Finalized>) -> Result<()> {
    start_observing(store, history, |_store| {}).await
}

/// [`start`], calling `observe` on the store after each entry of `history` replays.
async fn start_observing(
    store: &SharedStore,
    history: Vec<Finalized>,
    mut observe: impl FnMut(&SharedStore),
) -> Result<()> {
    let (config, _home) = sequencer_config();
    let channel = history
        .last()
        .map_or_else(CannedChannel::absent, |tip| CannedChannel {
            tip_slot: Some(Slot::from(tip.slot)),
            tip: Some(tip.msg),
            ..CannedChannel::absent()
        })
        .share();
    let channel_id = config.bedrock_config.channel_id;
    let executor = Box::pin(spawn_executor(
        config,
        MockStorageActor::spawn(store.mock()),
        spawn_bedrock_pool(move |_channel_id| channel.mock()),
    ))
    .await?;
    for update in finalized_updates(channel_id, history) {
        executor.ask(update).await?;
        observe(store);
    }
    executor.ask(ready(channel_id)).await?;
    executor.ask(GetLastBlockId).await?;
    Ok(())
}

/// The mint a finalized L1 deposit event injects, as the sequencer builds it.
fn deposit_tx(
    op_id: [u8; 32],
    recipient: AccountId,
    amount: bridge_core::BridgeAmount,
) -> LeeTransaction {
    let bridge_program_id = programs::bridge_account_id();
    // The receipt PDA carries the exactly-once check, so the deposit is addressed to it.
    let receipt = Actor::new(
        bridge_core::deposit_receipt_account_id(bridge_program_id, op_id),
        bridge_program_id,
    );
    let message = Message {
        admission_evidence: vec![lee::PublicAccountEvidence::Pda {
            program: bridge_program_id,
            seed: bridge_core::deposit_receipt_seed(op_id),
        }],
        ..Message::try_new(
            receipt,
            vec![
                receipt,
                Actor::native_balance(system_accounts::bridge_account_id()),
                Actor::native_balance(recipient),
            ],
            BTreeMap::new(),
            bridge_core::Message::Deposit {
                l1_deposit_op_id: op_id,
                recipient_id: recipient,
                amount,
            },
        )
        .expect("deposit message builds")
    };
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
    let junk = junk_at(MsgId::from([0xAA_u8; 32]), b"not a block", 15);
    let store = finalized_genesis_store().share();

    start(
        &store,
        vec![finalized_at(&genesis, 10), junk, finalized_at(&block2, 20)],
    )
    .await?;

    assert_reconstructed(&store, &block2, 20);
    Ok(())
}

/// The key that signs the offending inscriptions.
fn offender() -> Ed25519PublicKey {
    Ed25519Key::from_bytes(&[3; 32]).public_key()
}

/// An inscription carrying `payload`, signed by [`offender`] and finalized at `slot`, that does
/// not decode as a block.
fn signed_junk_at(payload: &[u8], slot: u64) -> Finalized {
    junk_at(MsgId::from([0xAA_u8; 32]), payload, slot).signed(offender())
}

/// `block`, signed by [`offender`] and finalized at `slot`.
fn signed_at(block: &Block, slot: u64) -> Finalized {
    finalized_at(block, slot).signed(offender())
}

/// A block that had to follow the final tip and does not is an offence, as on the follow path.
#[test]
async fn reconstruction_reports_a_misplaced_block() -> Result<()> {
    let genesis = genesis();
    let skipping_an_id = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
    let store = finalized_genesis_store().share();

    start(
        &store,
        vec![finalized_at(&genesis, 10), signed_at(&skipping_an_id, 20)],
    )
    .await?;

    assert!(
        store.lock().slash_record.is_some(),
        "the offence is recorded"
    );
    Ok(())
}

#[test]
async fn reconstruction_reports_an_invalid_block() -> Result<()> {
    let genesis = genesis();
    let mut corrupted = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    corrupted.header.hash = HashType([0xCD_u8; 32]);
    let store = finalized_genesis_store().share();

    start(
        &store,
        vec![finalized_at(&genesis, 10), signed_at(&corrupted, 20)],
    )
    .await?;

    assert!(
        store.lock().slash_record.is_some(),
        "the offence is recorded"
    );
    Ok(())
}

/// The replay names who signed each inscription, so a joining node judges the junk it carries
/// as the follow path would.
#[test]
async fn reconstruction_reports_an_undecodable_inscription() -> Result<()> {
    let genesis = genesis();
    let store = finalized_genesis_store().share();

    start(
        &store,
        vec![
            finalized_at(&genesis, 10),
            signed_junk_at(b"not a block", 15),
        ],
    )
    .await?;

    assert!(
        store.lock().slash_record.is_some(),
        "the offence is recorded"
    );
    Ok(())
}

/// An empty payload is a missed turn, which is not the offence of writing a non-block.
#[test]
async fn reconstruction_does_not_report_an_empty_inscription() -> Result<()> {
    let genesis = genesis();
    let store = finalized_genesis_store().share();

    start(
        &store,
        vec![finalized_at(&genesis, 10), signed_junk_at(b"", 15)],
    )
    .await?;

    assert!(store.lock().slash_record.is_none());
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
    chain.apply_reconstructed(parent, None, &BTreeSet::new());
    for block in held {
        store = with_head(store, block.clone());
        chain.apply_extension(vec![ChannelEntry {
            msg: mock_msg_of(block),
            parent,
            block: Some(block.clone()),
            finally_absent_keys: BTreeSet::new(),
            final_slot: None,
        }]);
        parent = mock_msg_of(block);
    }
    if final_msg.is_some() {
        store.channel_view = Some(chain.encode_view());
    }
    store.share()
}

/// A warm start re-reads history below the stored final entry, where a block that does not apply
/// had no final tip to follow, so it proves nothing.
#[test]
async fn a_reread_block_that_does_not_apply_is_not_reported() -> Result<()> {
    let [genesis, block2, _] = three_blocks();
    let skipping_an_id = produce_dummy_block(3, Some(genesis.header.hash), vec![]);
    let store = final_through(&block2, Some(mock_msg_of(&block2)), &[]);

    start(
        &store,
        vec![
            finalized_at(&genesis, 10),
            signed_at(&skipping_an_id, 15),
            finalized_at(&block2, 20),
        ],
    )
    .await?;

    assert!(store.lock().slash_record.is_none());
    Ok(())
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
            junk_at(junk, b"not a block", 25),
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

    // Restarting on the reconstructed store applies nothing again.
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

/// A deposit whose mint this node already holds final, re-recorded as its L1 event is read again
/// below the stored anchor. The channel serving the minting block back must settle the record,
/// as nothing later will ever mint it again.
#[test]
async fn a_verified_own_block_settles_its_deposit_records() -> Result<()> {
    let recipient = testnet_initial_state::initial_public_user_accounts()[0].account_id;
    let deposit_op_id = [0x1b_u8; 32];

    let genesis = genesis();
    let block2 = produce_dummy_block(
        2,
        Some(genesis.header.hash),
        vec![deposit_tx(deposit_op_id, recipient, 400)],
    );
    let store = CannedStore {
        pending_deposits: vec![PendingDepositEventRecord {
            deposit_op_id: HashType(deposit_op_id),
            source_tx_hash: HashType([0; 32]),
            amount: 400,
            metadata: Vec::new(),
        }],
        ..with_finalized(finalized_genesis_store(), block2.clone())
    }
    .share();

    start(
        &store,
        vec![finalized_at(&genesis, 10), finalized_at(&block2, 20)],
    )
    .await?;

    assert_eq!(store.lock().anchor, Some(anchor_at(&block2, 20)));
    assert!(store.lock().pending_deposits.is_empty());
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
            .actor_state(bridge_program_id)
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
