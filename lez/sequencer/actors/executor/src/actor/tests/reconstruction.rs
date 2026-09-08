//! Startup reconstruction: a starting executor replays the finalized channel
//! history its store misses, and refuses to start on a channel that serves a
//! different chain.

use std::collections::HashSet;

use anyhow::Result;
use common::{
    HashType,
    block::{Block, BlockMeta, HashableBlockData},
    test_utils::{
        claimed_producer_seed, produce_dummy_block, producer_account_for_testing,
        sequencer_sign_key_for_testing,
    },
    transaction::{LeeTransaction, clock_invocation, fee_invocation},
};
use kameo::actor::{ActorRef, Spawn as _};
use lee::{
    AccountId, PublicTransaction, V03State,
    public_transaction::{Message, WitnessSet},
};
use logos_blockchain_core::mantle::ops::channel::inscribe::Inscription;
use logos_blockchain_zone_sdk::ZoneBlock;
use ping_core::{ReceiverInstruction, ping_record_pda, receiver_config_account_id};
use sequencer_bedrock_actor::{
    mock::MockBedrockActor,
    protocol::{Checkpoint, HeaderId, MsgId, ReadChannel, Slot, ZoneMessage},
};
use sequencer_core::config::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute};
use sequencer_storage_actor::{
    mock::{Checkpoint as MockCheckpoint, MockStorageActor},
    protocol::{GetBlock, PendingCrossZoneDispatchRecord, StoreUpdateOutcome, ZoneAnchorRecord},
};
use tokio::test;

use super::sequencer_config;
use crate::ExecutorActor;

/// The peer zone a delivery comes from.
const PEER_ZONE: [u8; 32] = [0xbe_u8; 32];

/// What genesis leaves in the bridge account for deposits to mint from.
const BRIDGE_BALANCE: u128 = 1_000_000;

/// What the store holds when the executor starts.
struct StoredChain {
    /// Every stored block, genesis first.
    blocks: Vec<Block>,
    /// The irreversible tier; `None` until something finalizes.
    final_snapshot: Option<(V03State, BlockMeta)>,
    /// State after the last stored block.
    head_state: V03State,
    anchor: Option<ZoneAnchorRecord>,
    checkpoint: Option<Vec<u8>>,
    pending_dispatches: Vec<PendingCrossZoneDispatchRecord>,
}

impl StoredChain {
    /// Genesis stored but not finalized, as a fresh store seeds it.
    fn fresh() -> Self {
        let genesis = genesis();
        let head_state = applied(&testnet_initial_state::initial_state(false), &genesis);
        Self {
            blocks: vec![genesis],
            final_snapshot: None,
            head_state,
            anchor: None,
            checkpoint: None,
            pending_dispatches: Vec::new(),
        }
    }

    /// Genesis finalized, over a state where the test producer collects fees.
    fn finalized_genesis() -> Self {
        let genesis = genesis();
        let state = applied(
            &testnet_initial_state::initial_state(false)
                .with_public_accounts([claimed_producer_seed()]),
            &genesis,
        );
        Self {
            final_snapshot: Some((state.clone(), BlockMeta::from(&genesis))),
            head_state: state,
            ..Self::fresh()
        }
    }

    /// Genesis finalized over a state whose cross-zone inbox accepts pings from
    /// [`PEER_ZONE`], configured the way genesis configures it.
    fn cross_zone_genesis() -> Self {
        let cross_zone = CrossZoneConfig {
            peers: vec![CrossZonePeer {
                channel_id: PEER_ZONE,
                allowed_routes: vec![CrossZoneRoute {
                    src_account_id: programs::ping_sender().id().into(),
                    target_account_id: programs::ping_receiver().id().into(),
                    mint_cap: None,
                }],
                expected_block_signing_pubkeys: Vec::new(),
                min_committee_size: 0,
            }],
            source_authority: None,
            source_governance: None,
        };
        let mut state = testnet_initial_state::initial_state(true)
            .with_public_accounts([claimed_producer_seed()]);
        for tx in [
            cross_zone::build_wrapped_token_init_config_tx(&cross_zone),
            cross_zone::build_ping_sender_init_config_tx(),
            cross_zone::build_ping_receiver_init_config_tx(&cross_zone),
            cross_zone::build_bridge_lock_init_config_tx(),
            cross_zone::build_inbox_init_config_tx([0; 32]),
        ] {
            state
                .transition_from_public_transaction(&tx, 1, 0)
                .expect("cross-zone config initializes");
        }
        let genesis = genesis();
        Self {
            final_snapshot: Some((state.clone(), BlockMeta::from(&genesis))),
            head_state: state,
            ..Self::fresh()
        }
    }

    /// Genesis finalized over a state whose bridge account holds a balance, so a
    /// replayed deposit has a source to mint from.
    fn bridge_funded_genesis() -> Self {
        let mut state = testnet_initial_state::initial_state(false)
            .with_public_accounts([claimed_producer_seed()]);
        state
            .transition_from_public_transaction(&supply_bridge_tx(BRIDGE_BALANCE), 1, 0)
            .expect("genesis funds the bridge account");
        let genesis = genesis();
        Self {
            final_snapshot: Some((state.clone(), BlockMeta::from(&genesis))),
            head_state: state,
            ..Self::fresh()
        }
    }

    /// Extends the head tier with `block`.
    fn with_head(mut self, block: Block) -> Self {
        self.head_state = applied(&self.head_state, &block);
        self.blocks.push(block);
        self
    }

    /// Extends the chain with `block` and finalizes through it. A finalized block
    /// is never replayed, so its state is taken as is.
    fn with_finalized(mut self, block: Block) -> Self {
        self.final_snapshot = Some((self.head_state.clone(), BlockMeta::from(&block)));
        self.blocks.push(block);
        self
    }

    const fn with_anchor(mut self, anchor: ZoneAnchorRecord) -> Self {
        self.anchor = Some(anchor);
        self
    }

    fn with_checkpoint(mut self, checkpoint: Vec<u8>) -> Self {
        self.checkpoint = Some(checkpoint);
        self
    }

    fn with_pending_dispatch(mut self, record: PendingCrossZoneDispatchRecord) -> Self {
        self.pending_dispatches.push(record);
        self
    }

    /// Serves every read startup makes. Writes are left for each test to expect.
    fn into_mock(self) -> MockStorageActor {
        let Self {
            blocks,
            final_snapshot,
            head_state,
            anchor,
            checkpoint,
            pending_dispatches,
        } = self;
        let tip = blocks.last().map(BlockMeta::from);
        let tip_id = tip.as_ref().map(|tip| tip.id);

        let mut mock = MockStorageActor::new();
        mock.expect_handle_get_first_block_id()
            .returning(|_msg, _ctx| Ok(Some(1)));
        mock.expect_handle_get_last_block_id()
            .returning(move |_msg, _ctx| Ok(tip_id));
        mock.expect_handle_get_latest_block_meta()
            .returning(move |_msg, _ctx| Ok(tip.clone()));
        mock.expect_handle_get_lee_state()
            .returning(move |_msg, _ctx| Ok(Some(head_state.clone())));
        mock.expect_handle_get_final_snapshot()
            .returning(move |_msg, _ctx| Ok(final_snapshot.clone()));
        mock.expect_handle_get_all_blocks().returning({
            let blocks = blocks.clone();
            move |_msg, _ctx| Ok(blocks.clone())
        });
        mock.expect_handle_get_block()
            .returning(move |GetBlock { block_id }, _ctx| {
                Ok(blocks
                    .iter()
                    .find(|block| block.header.block_id == block_id)
                    .cloned())
            });
        mock.expect_handle_get_zone_anchor()
            .returning(move |_msg, _ctx| Ok(anchor));
        mock.expect_handle_get_zone_checkpoint_bytes()
            .returning(move |_msg, _ctx| Ok(checkpoint.clone()));
        mock.expect_handle_get_channel_cursor()
            .returning(|_msg, _ctx| Ok(None));
        mock.expect_handle_get_slash_record_bytes()
            .returning(|_msg, _ctx| Ok(None));
        mock.expect_handle_get_pending_cross_zone_dispatches()
            .returning(move |_msg, _ctx| Ok(pending_dispatches.clone()));
        mock.expect_handle_raise_published_high_water()
            .returning(|_msg, _ctx| Ok(()));
        mock.expect_handle_get_dead_letter_dispatches()
            .returning(|_msg, _ctx| Ok(Vec::new()));
        mock
    }
}

/// Expects the anchor to move onto `block`, which the store already holds, at `slot`.
fn expect_anchor(store: &mut MockStorageActor, block: &Block, slot: u64) {
    let anchor = ZoneAnchorRecord {
        slot,
        block_id: block.header.block_id,
        hash: block.header.hash,
    };
    store
        .expect_handle_set_zone_anchor()
        .withf(move |msg, _ctx| msg.anchor == anchor)
        .times(1)
        .returning(|_msg, _ctx| Ok(()));
}

/// Expects `block`, read off the channel at `slot`, persisted as final and as
/// the head tip.
fn expect_reconstructed(store: &mut MockStorageActor, block: &Block, slot: u64) {
    let (block_id, hash) = (block.header.block_id, block.header.hash);
    store
        .expect_handle_apply_store_update()
        .withf(move |update, _ctx| {
            update
                .blocks
                .iter()
                .map(|stored| stored.header.hash)
                .eq([hash])
                && update.head_tip.as_ref().map(|tip| tip.hash) == Some(hash)
                && update.finalized_up_to == Some(block_id)
                && update.zone_anchor
                    == Some(ZoneAnchorRecord {
                        slot,
                        block_id,
                        hash,
                    })
        })
        .times(1)
        .returning(|_msg, _ctx| Ok(StoreUpdateOutcome::default()));
}

/// A Bedrock whose channel ends at `tip_slot` (`None`: no channel) and holds
/// `messages` as finalized history.
fn channel_serving(tip_slot: Option<Slot>, messages: Vec<(ZoneMessage, Slot)>) -> MockBedrockActor {
    let mut mock = MockBedrockActor::default();
    mock.expect_handle_check_channel_exists()
        .returning(move |_msg, _ctx| Ok(tip_slot.is_some()));
    mock.expect_handle_get_channel_tip_slot()
        .returning(move |_msg, _ctx| Ok(tip_slot));
    mock.expect_handle_read_channel()
        .returning(move |ReadChannel { after }, _ctx| {
            let messages: Vec<_> = messages
                .iter()
                .filter(|(_, slot)| after.is_none_or(|after| *slot > after))
                .cloned()
                .collect();
            Ok(Box::pin(futures::stream::iter(messages)))
        });
    mock.expect_handle_check_is_our_turn()
        .returning(|_msg, _ctx| true);
    mock
}

/// Starts an executor over `storage_ref` against `bedrock_ref`.
async fn start(
    storage_ref: &ActorRef<MockStorageActor>,
    bedrock_ref: &ActorRef<MockBedrockActor>,
) -> Result<()> {
    let (config, _home) = sequencer_config();
    ExecutorActor::new(config, storage_ref.clone(), bedrock_ref.clone())
        .await
        .map(drop)
        .map_err(anyhow::Error::new)
}

fn assert_refused(started: Result<()>, reason: &str) {
    let err = started.expect_err("startup must refuse this channel");
    assert!(
        format!("{err:#}").contains(reason),
        "startup failed for another reason: {err:#}"
    );
}

/// Genesis the way a stakeless node seeds it: only the fee and clock tail.
fn genesis() -> Block {
    block_at(1, HashType([0; 32]), 0)
}

/// A valid empty block, like [`produce_dummy_block`] but at `timestamp`.
fn block_at(id: u64, prev: HashType, timestamp: u64) -> Block {
    HashableBlockData {
        block_id: id,
        prev_block_hash: prev,
        timestamp,
        transactions: vec![
            LeeTransaction::Public(fee_invocation(
                fee_core::BlockFeeSummary::default(),
                producer_account_for_testing(),
            )),
            LeeTransaction::Public(clock_invocation(timestamp)),
        ],
    }
    .into_pending_block(&sequencer_sign_key_for_testing())
}

fn applied(state: &V03State, block: &Block) -> V03State {
    let mut next = state.clone();
    chain_state::apply_block_to_state(block, &mut next).expect("test block applies");
    next
}

fn channel_message(block: &Block, slot: u64) -> (ZoneMessage, Slot) {
    let bytes = borsh::to_vec(block).expect("block serializes");
    let message = ZoneMessage::Block(ZoneBlock {
        id: MsgId::from(block.header.hash.0),
        data: Inscription::try_from(bytes.as_slice()).expect("block fits an inscription"),
    });
    (message, Slot::from(slot))
}

fn checkpoint_bytes() -> Vec<u8> {
    serde_json::to_vec(&Checkpoint {
        last_msg_id: MsgId::from([0; 32]),
        pending_txs: Vec::new(),
        lib: HeaderId::from([0; 32]),
        lib_slot: Slot::from(0),
        channel_notes: Vec::new(),
        finalized_config: MsgId::root(),
    })
    .expect("checkpoint serializes")
}

fn peer_block_hash(src_block_id: u64) -> [u8; 32] {
    let mut hash = [0_u8; 32];
    hash[..8].copy_from_slice(&src_block_id.to_le_bytes());
    hash
}

/// A delivery of `payload` to the ping receiver, read off peer block `src_block_id`.
fn dispatch_tx(src_block_id: u64, payload: &[u8]) -> LeeTransaction {
    let receiver_id: AccountId = programs::ping_receiver().id().into();
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
            src_account_id: programs::ping_sender().id().into(),
        },
        receiver_id,
        &[
            receiver_config_account_id(receiver_id).into_value(),
            ping_record_pda(receiver_id).into_value(),
        ],
        instruction,
    ))
}

/// Genesis' faucet transfer into the bridge account, as `SupplyBridgeAccount` builds it.
fn supply_bridge_tx(balance: u128) -> PublicTransaction {
    let message = Message::try_new(
        programs::faucet().id().into(),
        vec![
            system_accounts::faucet_account_id(),
            system_accounts::bridge_account_id(),
        ],
        Vec::new(),
        faucet_core::Instruction::GenesisTransfer { amount: balance },
    )
    .expect("genesis transfer message builds");
    PublicTransaction::new(message, WitnessSet::from_raw_parts(Vec::new()))
}

/// The mint a finalized L1 deposit event injects, as the sequencer builds it.
fn deposit_tx(op_id: [u8; 32], recipient: AccountId, amount: u64) -> LeeTransaction {
    let bridge_program_id: AccountId = programs::bridge().id().into();
    let message = Message::try_new(
        bridge_program_id,
        vec![
            system_accounts::bridge_account_id(),
            recipient,
            // The receipt PDA carries the exactly-once check, so the program
            // needs it in the account list.
            bridge_core::deposit_receipt_account_id(bridge_program_id, op_id),
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
    let junk = ZoneMessage::Block(ZoneBlock {
        id: MsgId::from([0xAA_u8; 32]),
        data: Inscription::try_from(b"not a block".as_slice()).expect("fits an inscription"),
    });

    let mut store = StoredChain::finalized_genesis().into_mock();
    expect_anchor(&mut store, &genesis, 10);
    expect_reconstructed(&mut store, &block2, 20);
    let bedrock = channel_serving(
        Some(Slot::from(20)),
        vec![
            channel_message(&genesis, 10),
            (junk, Slot::from(15)),
            channel_message(&block2, 20),
        ],
    );

    let storage_ref = MockStorageActor::spawn(store);
    let bedrock_ref = MockBedrockActor::spawn(bedrock);
    start(&storage_ref, &bedrock_ref)
        .await
        .expect("an undecodable inscription must not abort startup");
    storage_ref.ask(MockCheckpoint).await?;
    Ok(())
}

#[test]
async fn reconstructs_missing_channel_blocks_into_the_store() -> Result<()> {
    let genesis = genesis();
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let messages = vec![channel_message(&genesis, 10), channel_message(&block2, 20)];

    let mut store = StoredChain::finalized_genesis().into_mock();
    expect_anchor(&mut store, &genesis, 10);
    expect_reconstructed(&mut store, &block2, 20);

    let storage_ref = MockStorageActor::spawn(store);
    let bedrock_ref =
        MockBedrockActor::spawn(channel_serving(Some(Slot::from(20)), messages.clone()));
    start(&storage_ref, &bedrock_ref)
        .await
        .expect("reconstruct");
    storage_ref.ask(MockCheckpoint).await?;

    // Restarting on the reconstructed store applies nothing again.
    let mut restarted_store = StoredChain::finalized_genesis()
        .with_finalized(block2.clone())
        .with_anchor(ZoneAnchorRecord {
            slot: 20,
            block_id: 2,
            hash: block2.header.hash,
        })
        .into_mock();
    expect_anchor(&mut restarted_store, &block2, 20);

    let restarted_storage_ref = MockStorageActor::spawn(restarted_store);
    let restarted_bedrock_ref =
        MockBedrockActor::spawn(channel_serving(Some(Slot::from(20)), messages));
    start(&restarted_storage_ref, &restarted_bedrock_ref)
        .await
        .expect("reconstruct idempotent");
    restarted_storage_ref.ask(MockCheckpoint).await?;
    Ok(())
}

#[test]
async fn fails_when_channel_serves_a_divergent_block() {
    let genesis = genesis();
    let store = StoredChain::finalized_genesis().with_anchor(ZoneAnchorRecord {
        slot: 100,
        block_id: 1,
        hash: genesis.header.hash,
    });

    // The channel serves a different block at the anchor id/slot.
    let mut tampered = genesis;
    tampered.header.hash = HashType([9_u8; 32]);
    let bedrock = channel_serving(Some(Slot::from(100)), vec![channel_message(&tampered, 100)]);

    let storage_ref = MockStorageActor::spawn(store.into_mock());
    let bedrock_ref = MockBedrockActor::spawn(bedrock);
    assert_refused(
        start(&storage_ref, &bedrock_ref).await,
        "diverges from the Bedrock channel",
    );
}

#[test]
async fn fails_when_channel_is_missing() {
    let genesis = genesis();
    let store = StoredChain::finalized_genesis().with_anchor(ZoneAnchorRecord {
        slot: 100,
        block_id: 1,
        hash: genesis.header.hash,
    });

    // Anchor present, but the channel does not exist on the connected chain.
    let storage_ref = MockStorageActor::spawn(store.into_mock());
    let bedrock_ref = MockBedrockActor::spawn(channel_serving(None, vec![]));
    assert_refused(
        start(&storage_ref, &bedrock_ref).await,
        "diverges from the Bedrock channel",
    );
}

// The following cases exercise the divergence branches of
// `apply_reconstructed_block` reached with no recorded anchor, so the block's own
// validation fires rather than the up-front `AnchorConsistencyCheck`.

#[test]
async fn fails_when_channel_reinscribes_genesis_with_a_different_hash() {
    // Fresh store, no anchor. The channel serves a genesis at the same id but a
    // different hash — a foreign chain reinscribing genesis.
    let mut reinscribed = genesis();
    reinscribed.header.hash = HashType([0xAB_u8; 32]);
    let bedrock = channel_serving(
        Some(Slot::from(10)),
        vec![channel_message(&reinscribed, 10)],
    );

    let storage_ref = MockStorageActor::spawn(StoredChain::fresh().into_mock());
    let bedrock_ref = MockBedrockActor::spawn(bedrock);
    assert_refused(
        start(&storage_ref, &bedrock_ref).await,
        "does not extend local tip",
    );
}

#[test]
async fn fails_when_a_below_tip_channel_block_does_not_validate() {
    // A below-tip block re-served with a corrupted hash. Holding a different
    // block at that id is not itself grounds to abort — the head tier is
    // reorg-able — but this one's header hash does not cover its contents, so it
    // parks on validation.
    let genesis = genesis();
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let mut corrupted = block2.clone();
    corrupted.header.hash = HashType([0xCD_u8; 32]);
    let bedrock = channel_serving(Some(Slot::from(10)), vec![channel_message(&corrupted, 10)]);

    let store = StoredChain::finalized_genesis().with_head(block2);
    let storage_ref = MockStorageActor::spawn(store.into_mock());
    let bedrock_ref = MockBedrockActor::spawn(bedrock);
    assert_refused(
        start(&storage_ref, &bedrock_ref).await,
        "does not extend local tip",
    );
}

#[test]
async fn fails_when_a_channel_block_is_numbered_below_genesis() {
    // A block numbered below our genesis — a foreign chain with a lower
    // numbering. Nothing local sits at that id, so it goes straight to
    // validation and parks there.
    let mut foreign = genesis();
    foreign.header.block_id = 0;
    let bedrock = channel_serving(Some(Slot::from(10)), vec![channel_message(&foreign, 10)]);

    let storage_ref = MockStorageActor::spawn(StoredChain::fresh().into_mock());
    let bedrock_ref = MockBedrockActor::spawn(bedrock);
    assert_refused(
        start(&storage_ref, &bedrock_ref).await,
        "does not extend local tip",
    );
}

#[test]
async fn fails_when_a_channel_block_does_not_extend_the_tip() {
    // A block claiming an id far past genesis does not chain onto the local tip.
    let mut orphan = genesis();
    orphan.header.block_id = 6;
    let bedrock = channel_serving(Some(Slot::from(10)), vec![channel_message(&orphan, 10)]);

    let storage_ref = MockStorageActor::spawn(StoredChain::fresh().into_mock());
    let bedrock_ref = MockBedrockActor::spawn(bedrock);
    assert_refused(
        start(&storage_ref, &bedrock_ref).await,
        "does not extend local tip",
    );
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

    // The anchor tracks the block we hold, never the one we dropped.
    let mut store = StoredChain::finalized_genesis()
        .with_finalized(block2.clone())
        .into_mock();
    expect_anchor(&mut store, &genesis, 10);
    expect_anchor(&mut store, &block2, 20);
    let bedrock = channel_serving(
        Some(Slot::from(999)),
        vec![
            channel_message(&genesis, 10),
            channel_message(&block2, 20),
            channel_message(&competitor, 999),
        ],
    );

    let storage_ref = MockStorageActor::spawn(store);
    let bedrock_ref = MockBedrockActor::spawn(bedrock);
    start(&storage_ref, &bedrock_ref)
        .await
        .expect("a duplicate height the final tier settled must not abort startup");
    storage_ref.ask(MockCheckpoint).await?;
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

    let mut store = StoredChain::finalized_genesis()
        .with_head(competitor)
        .into_mock();
    expect_anchor(&mut store, &genesis, 10);
    expect_reconstructed(&mut store, &block2, 20);
    let bedrock = channel_serving(
        Some(Slot::from(20)),
        vec![channel_message(&genesis, 10), channel_message(&block2, 20)],
    );

    let storage_ref = MockStorageActor::spawn(store);
    let bedrock_ref = MockBedrockActor::spawn(bedrock);
    start(&storage_ref, &bedrock_ref)
        .await
        .expect("finalized history must replace a conflicting head block");
    storage_ref.ask(MockCheckpoint).await?;
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
    let block2_hash = block2.header.hash;
    let record_id = ping_record_pda(programs::ping_receiver().id().into());

    let mut store = StoredChain::cross_zone_genesis()
        .with_pending_dispatch(record)
        .into_mock();
    expect_anchor(&mut store, &genesis, 10);
    // The delivery reaches its target program exactly once, and its record goes.
    store
        .expect_handle_apply_store_update()
        .withf(move |update, _ctx| {
            update
                .blocks
                .iter()
                .map(|block| block.header.hash)
                .eq([block2_hash])
                && update.finalized_dispatch_records == HashSet::from([key])
                && update
                    .head_state
                    .get_account_by_id(record_id)
                    .data
                    .into_inner()
                    == payload
        })
        .times(1)
        .returning(|_msg, _ctx| Ok(StoreUpdateOutcome::default()));
    let bedrock = channel_serving(
        Some(Slot::from(20)),
        vec![channel_message(&genesis, 10), channel_message(&block2, 20)],
    );

    let storage_ref = MockStorageActor::spawn(store);
    let bedrock_ref = MockBedrockActor::spawn(bedrock);
    start(&storage_ref, &bedrock_ref)
        .await
        .expect("reconstruct");
    storage_ref.ask(MockCheckpoint).await?;
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

    let mut store = StoredChain::finalized_genesis()
        .with_finalized(block2.clone())
        .with_pending_dispatch(record)
        .into_mock();
    expect_anchor(&mut store, &genesis, 10);
    expect_anchor(&mut store, &block2, 20);
    store
        .expect_handle_drop_settled_cross_zone_dispatches()
        .withf(move |msg, _ctx| msg.message_keys == HashSet::from([key]))
        .times(1)
        .returning(|_msg, _ctx| Ok(()));
    let bedrock = channel_serving(
        Some(Slot::from(20)),
        vec![channel_message(&genesis, 10), channel_message(&block2, 20)],
    );

    let storage_ref = MockStorageActor::spawn(store);
    let bedrock_ref = MockBedrockActor::spawn(bedrock);
    start(&storage_ref, &bedrock_ref)
        .await
        .expect("reconstruct");
    storage_ref.ask(MockCheckpoint).await?;
    Ok(())
}

#[test]
async fn committed_local_against_missing_channel_fails_without_anchor() {
    // A sequencer that has committed blocks — a non-genesis tip plus a persisted
    // checkpoint — but only ever produced (so it never recorded a per-block
    // anchor). Restarting it against a wiped/missing channel must still fail,
    // driven by the committed-blocks invariant rather than an anchor probe.
    let genesis = genesis();
    let block2 = produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    let store = StoredChain::finalized_genesis()
        .with_finalized(block2)
        .with_checkpoint(checkpoint_bytes());

    let storage_ref = MockStorageActor::spawn(store.into_mock());
    let bedrock_ref = MockBedrockActor::spawn(channel_serving(None, vec![]));
    assert_refused(
        start(&storage_ref, &bedrock_ref).await,
        "no longer exists on the connected chain",
    );
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
    let receipt_id =
        bridge_core::deposit_receipt_account_id(programs::bridge().id().into(), deposit_op_id);

    let genesis = genesis();
    let block2 = produce_dummy_block(
        2,
        Some(genesis.header.hash),
        vec![deposit_tx(deposit_op_id, recipient, deposit_amount)],
    );
    let block2_hash = block2.header.hash;

    let mut store = StoredChain::bridge_funded_genesis().into_mock();
    expect_anchor(&mut store, &genesis, 10);
    // The mint lands once and the record its L1 event left behind is dropped.
    store
        .expect_handle_apply_store_update()
        .withf(move |update, _ctx| {
            update
                .blocks
                .iter()
                .map(|stored| stored.header.hash)
                .eq([block2_hash])
                && update.finalized_deposit_records == HashSet::from([HashType(deposit_op_id)])
                && update.head_state.get_account_by_id(recipient).balance
                    == funded + u128::from(deposit_amount)
                && update
                    .head_state
                    .get_account_by_id(receipt_id)
                    .program_owner
                    == programs::bridge().id().into()
        })
        .times(1)
        .returning(|_msg, _ctx| Ok(StoreUpdateOutcome::default()));
    let bedrock = channel_serving(
        Some(Slot::from(20)),
        vec![channel_message(&genesis, 10), channel_message(&block2, 20)],
    );

    let storage_ref = MockStorageActor::spawn(store);
    let bedrock_ref = MockBedrockActor::spawn(bedrock);
    start(&storage_ref, &bedrock_ref)
        .await
        .expect("reconstruct");
    storage_ref.ask(MockCheckpoint).await?;
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
