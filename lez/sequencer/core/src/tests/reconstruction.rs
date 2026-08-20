#![expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "We don't care about it in tests"
)]

use chain_state::ChainState;
use common::block::Block;
use logos_blockchain_core::mantle::ops::channel::{MsgId, inscribe::Inscription};
use logos_blockchain_zone_sdk::{Slot, ZoneBlock, ZoneMessage, sequencer::SequencerCheckpoint};
use sequencer_storage_actor::{
    StorageActorTrait,
    protocol::{
        AddPendingCrossZoneDispatches, AddPendingDepositEvent, ConsumeUnseenWithdrawCount,
        GetPendingDepositEvents, WithdrawalReconciliationKey, ZoneAnchorRecord,
    },
};
use tokio::sync::Mutex;

use super::*;
use crate::{
    SequencerCore, block_store::SequencerStore, config::GenesisAction, mock::MockBlockPublisher,
};

fn checkpoint(slot: u64) -> SequencerCheckpoint {
    SequencerCheckpoint {
        last_msg_id: [0; 32].into(),
        pending_txs: vec![],
        lib: [42; 32].into(),
        lib_slot: Slot::from(slot),
    }
}

/// Fresh `(store, chain)` pair for a reconstruction target, as
/// `start_from_config` would build them before the publisher starts.
// TODO: Revisit this function, it relies to heavily on internal implementation details.
// Will be possible to address this once block publisher is moved to another actor(-s).
async fn fresh_store_and_chain(
    config: &SequencerConfig,
) -> (SequencerStore<StorageActor>, Mutex<ChainState>) {
    let storage = StorageActor::new(&config.db_path()).expect("Failed to initialize storage actor");
    let storage_ref = StorageActor::spawn(storage);
    // What `start_from_config` does before it opens a store, mirrored here
    // because these cases drive `verify_and_reconstruct` directly.
    let signing_key = lee::PrivateKey::try_new(config.signing_key).unwrap();
    let bootstrap_sequencer_key = Some(test_bootstrap_sequencer_key(config));
    SequencerCore::<MockBlockPublisher>::seed_genesis_if_absent(
        &storage_ref,
        &signing_key,
        bootstrap_sequencer_key,
        config,
    )
    .await;
    let store = SequencerStore::new(storage_ref, signing_key)
        .await
        .expect("open store");
    let state = store
        .get_lee_state()
        .await
        .expect("read state")
        .expect("seeded store holds a state");
    let chain = Mutex::new(
        SequencerCore::<MockBlockPublisher>::restore_chain_state(config, &store, &state).await,
    );
    (store, chain)
}

fn block_to_channel_message(block: &Block, slot: u64) -> (ZoneMessage, SequencerCheckpoint) {
    let bytes = borsh::to_vec(block).expect("serialize block");
    let message = ZoneMessage::Block(ZoneBlock {
        id: MsgId::from([0_u8; 32]),
        data: Inscription::try_from(bytes.as_slice()).expect("inscription"),
    });
    (message, checkpoint(slot))
}

/// Collects a sequencer's whole chain (genesis..=tip) into a canned channel,
/// one block per slot at `slot_step` spacing.
async fn channel_from_store<S: StorageActorTrait>(
    store: &SequencerStore<S>,
    slot_step: u64,
) -> Vec<(ZoneMessage, SequencerCheckpoint)> {
    let genesis_id = store.genesis_id();
    let tip_id = store
        .latest_block_meta()
        .await
        .expect("tip")
        .expect("present")
        .id;
    let mut messages = Vec::new();
    for (index, id) in (genesis_id..=tip_id).enumerate() {
        let block = store.block_at_id(id).await.expect("read").expect("present");
        messages.push(block_to_channel_message(
            &block,
            (index as u64 + 1) * slot_step,
        ));
    }
    messages
}

#[tokio::test]
async fn reconstructs_missing_channel_blocks_into_fresh_store() {
    // Sequencer A produces a few blocks; treat its chain as the channel.
    let config_a = setup_sequencer_config();
    let (mut seq_a, _handle_a) = start_sequencer(config_a.clone()).await;
    seq_a.run_production_turn().await.unwrap();
    seq_a.run_production_turn().await.unwrap();
    let tip_a = seq_a
        .block_store()
        .latest_block_meta()
        .await
        .unwrap()
        .unwrap();

    let messages = channel_from_store(seq_a.block_store(), 10).await;
    let tip_slot = messages.last().unwrap().1.lib_slot;
    let channel_id = config_a.bedrock_config.channel_id;

    // Sequencer B starts from a fresh store and reconstructs A's chain.
    let config_b = setup_sequencer_config();
    let (store_b, chain_b) = fresh_store_and_chain(&config_b).await;
    let mock_b = MockBlockPublisher::with_canned_channel(channel_id, Some(tip_slot), messages);

    let channel_was_empty = SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(
        &mock_b, &store_b, &chain_b, true,
    )
    .await
    .expect("reconstruct");
    assert!(!channel_was_empty);

    let tip_b = store_b.latest_block_meta().await.unwrap().unwrap();
    assert_eq!(tip_b.id, tip_a.id);
    assert_eq!(tip_b.hash, tip_a.hash);

    // State matches: initial account balances agree with sequencer A.
    let state_b = chain_b.lock().await.head_state().clone();
    let state_a = seq_a.chain().lock().await.head_state().clone();
    for account in initial_public_user_accounts() {
        assert_eq!(
            state_b.get_account_by_id(account.account_id).balance,
            state_a.get_account_by_id(account.account_id).balance,
        );
    }

    let anchor = store_b
        .get_zone_anchor()
        .await
        .unwrap()
        .expect("anchor recorded");
    assert_eq!(anchor.block_id, tip_a.id);
    assert_eq!(anchor.checkpoint.lib_slot, tip_slot);

    // Re-running is idempotent: everything is already applied, no error.
    let channel_was_empty = SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(
        &mock_b, &store_b, &chain_b, true,
    )
    .await
    .expect("reconstruct idempotent");
    assert!(!channel_was_empty);
    assert_eq!(
        store_b.latest_block_meta().await.unwrap().unwrap().id,
        tip_a.id
    );
}

#[tokio::test]
async fn fails_when_channel_serves_a_divergent_block() {
    let config = setup_sequencer_config();
    let (store, chain) = fresh_store_and_chain(&config).await;

    // Anchor on the local genesis at some slot.
    let genesis_id = store.genesis_id();
    let genesis = store.block_at_id(genesis_id).await.unwrap().unwrap();
    let anchor_slot = 100_u64;
    let anchor_checkpoint = checkpoint(anchor_slot);
    store
        .set_zone_anchor(ZoneAnchorRecord {
            checkpoint: anchor_checkpoint,
            block_id: genesis_id,
            hash: genesis.header.hash,
        })
        .await
        .unwrap();

    // The channel serves a different block at the anchor id/slot.
    let mut tampered = genesis.clone();
    tampered.header.hash = HashType([9_u8; 32]);
    let messages = vec![block_to_channel_message(&tampered, anchor_slot)];
    let mock = MockBlockPublisher::with_canned_channel(
        config.bedrock_config.channel_id,
        Some(Slot::from(anchor_slot)),
        messages,
    );

    let result =
        SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(&mock, &store, &chain, true)
            .await;
    assert!(result.is_err(), "divergent channel must abort startup");
}

#[tokio::test]
async fn fails_when_channel_is_missing() {
    let config = setup_sequencer_config();
    let (store, chain) = fresh_store_and_chain(&config).await;
    let genesis_id = store.genesis_id();
    let genesis = store.block_at_id(genesis_id).await.unwrap().unwrap();
    store
        .set_zone_anchor(ZoneAnchorRecord {
            checkpoint: checkpoint(100),
            block_id: genesis_id,
            hash: genesis.header.hash,
        })
        .await
        .unwrap();

    // Anchor present, but the channel does not exist on the connected chain.
    let mock =
        MockBlockPublisher::with_canned_channel(config.bedrock_config.channel_id, None, vec![]);
    let result =
        SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(&mock, &store, &chain, true)
            .await;
    assert!(result.is_err(), "missing channel must abort startup");
}

// The following cases exercise the divergence branches of
// `apply_reconstructed_block` reached with no recorded anchor, so the block's own
// validation fires rather than the up-front `AnchorConsistencyCheck`.

#[tokio::test]
async fn fails_when_channel_reinscribes_genesis_with_a_different_hash() {
    let config = setup_sequencer_config();
    let (store, chain) = fresh_store_and_chain(&config).await;

    // Fresh store, no anchor. The channel serves a genesis at the same id but a
    // different hash — a foreign chain reinscribing genesis.
    let mut reinscribed = store
        .block_at_id(store.genesis_id())
        .await
        .unwrap()
        .unwrap();
    reinscribed.header.hash = HashType([0xAB_u8; 32]);

    let messages = vec![block_to_channel_message(&reinscribed, 10)];
    let mock = MockBlockPublisher::with_canned_channel(
        config.bedrock_config.channel_id,
        Some(Slot::from(10)),
        messages,
    );
    let result =
        SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(&mock, &store, &chain, true)
            .await;
    assert!(
        result.is_err(),
        "a reinscribed genesis with a different hash must abort startup"
    );
}

#[tokio::test]
async fn fails_when_a_below_tip_channel_block_does_not_validate() {
    // A sequencer that committed blocks past genesis but never recorded an anchor.
    let config = setup_sequencer_config();
    let (mut seq, _handle) = start_sequencer(config.clone()).await;
    seq.run_production_turn().await.unwrap();
    seq.run_production_turn().await.unwrap();

    // A below-tip block re-served with a corrupted hash. Holding a different
    // block at that id is not itself grounds to abort — the head tier is
    // reorg-able — but this one's header hash does not cover its contents, so it
    // parks on validation.
    let below_tip_id = seq.block_store().genesis_id() + 1;
    let mut block = seq
        .block_store()
        .block_at_id(below_tip_id)
        .await
        .unwrap()
        .unwrap();
    block.header.hash = HashType([0xCD_u8; 32]);

    let messages = vec![block_to_channel_message(&block, 10)];
    let mock = MockBlockPublisher::with_canned_channel(
        config.bedrock_config.channel_id,
        Some(Slot::from(10)),
        messages,
    );
    let result = SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(
        &mock, &seq.store, &seq.chain, true,
    )
    .await;
    assert!(
        result.is_err(),
        "an unverifiable below-tip block must abort startup"
    );
}

#[tokio::test]
async fn fails_when_a_channel_block_is_numbered_below_genesis() {
    let config = setup_sequencer_config();
    let (store, chain) = fresh_store_and_chain(&config).await;

    // A block numbered below our genesis — a foreign chain with a lower
    // numbering. Nothing local sits at that id, so it goes straight to
    // validation and parks there.
    let mut foreign = store
        .block_at_id(store.genesis_id())
        .await
        .unwrap()
        .unwrap();
    foreign.header.block_id = store.genesis_id() - 1;

    let messages = vec![block_to_channel_message(&foreign, 10)];
    let mock = MockBlockPublisher::with_canned_channel(
        config.bedrock_config.channel_id,
        Some(Slot::from(10)),
        messages,
    );
    let result =
        SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(&mock, &store, &chain, true)
            .await;
    assert!(
        result.is_err(),
        "a channel block below the local range must abort startup"
    );
}

#[tokio::test]
async fn fails_when_a_channel_block_does_not_extend_the_tip() {
    let config = setup_sequencer_config();
    let (store, chain) = fresh_store_and_chain(&config).await;

    // A block claiming an id far past genesis does not chain onto the local tip.
    let mut orphan = store
        .block_at_id(store.genesis_id())
        .await
        .unwrap()
        .unwrap();
    orphan.header.block_id = store.genesis_id() + 5;

    let messages = vec![block_to_channel_message(&orphan, 10)];
    let mock = MockBlockPublisher::with_canned_channel(
        config.bedrock_config.channel_id,
        Some(Slot::from(10)),
        messages,
    );
    let result =
        SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(&mock, &store, &chain, true)
            .await;
    assert!(
        result.is_err(),
        "a non-contiguous channel block must abort startup"
    );
}

// The two cases below reproduce the real startup order: zone-sdk's cold-start
// backfill runs inside `BP::new` and populates the store *before*
// `verify_and_reconstruct`, so reconstruction re-reads history it already holds.
// A conflict there is a competing sequencer, not a foreign chain.

/// The channel carries two inscriptions for one block id — competing sequencers
/// around a turn change — and the final tier already settled that height.
/// Finality is irreversible, so the loser is ignored rather than fatal.
#[tokio::test]
async fn reconstruction_ignores_a_duplicate_height_the_final_tier_settled() {
    // Sequencer A's chain is what the channel finalized.
    let config_a = setup_sequencer_config();
    let (mut seq_a, _mempool_a) = start_sequencer(config_a.clone()).await;
    seq_a.run_production_turn().await.unwrap();
    let tip_a = seq_a
        .block_store()
        .latest_block_meta()
        .await
        .unwrap()
        .unwrap();
    let mut messages = channel_from_store(seq_a.block_store(), 10).await;
    let settled_slot = messages.last().unwrap().1.lib_slot;

    // Sequencer B: the cold-start backfill finalizes A's chain into its store.
    let (seq_b, mempool_b) = start_sequencer(setup_sequencer_config()).await;
    let mut finalized: Vec<(MsgId, Block)> = Vec::new();
    for id in seq_b.block_store().genesis_id()..=tip_a.id {
        let block = seq_a.block_store().block_at_id(id).await.unwrap().unwrap();
        finalized.push((
            MsgId::from([u8::try_from(id).expect("should be u8"); 32]),
            block,
        ));
    }
    apply_follow_update(
        seq_b.block_store().storage_ref(),
        &seq_b.chain(),
        &mempool_b,
        FollowUpdate {
            finalized,
            ..empty_follow_update()
        },
    )
    .await;
    assert_eq!(
        seq_b
            .chain()
            .lock()
            .await
            .final_tip()
            .expect("backfill finalized A's chain")
            .block_id,
        tip_a.id,
    );

    // A competitor published its own block at that same height.
    let parent = seq_a
        .block_store()
        .block_at_id(tip_a.id - 1)
        .await
        .unwrap()
        .unwrap();
    let competitor =
        common::test_utils::produce_dummy_block(tip_a.id, Some(parent.header.hash), vec![]);
    assert_ne!(competitor.header.hash, tip_a.hash);
    messages.push(block_to_channel_message(&competitor, 999));

    let mock_b = MockBlockPublisher::with_canned_channel(
        config_a.bedrock_config.channel_id,
        Some(Slot::from(999)),
        messages,
    );
    SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(
        &mock_b,
        &seq_b.store,
        &seq_b.chain,
        true,
    )
    .await
    .expect("a duplicate height the final tier settled must not abort startup");

    let tip_b = seq_b
        .block_store()
        .latest_block_meta()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tip_b.hash, tip_a.hash, "the finalized block stands");

    // The anchor tracks the block we hold, never the one we dropped.
    let anchor = seq_b
        .block_store()
        .get_zone_anchor()
        .await
        .unwrap()
        .expect("anchor");
    assert_eq!(anchor.checkpoint.lib_slot, settled_slot);
    assert_eq!(anchor.hash, tip_a.hash);
}

/// A block the head tier holds is reorg-able by construction, so finalized
/// channel history at that height wins and the head rebases onto it.
#[tokio::test]
async fn reconstruction_replaces_a_conflicting_head_block_with_finalized_history() {
    // Sequencer A's chain is what the channel finalized.
    let config_a = setup_sequencer_config();
    let (mut seq_a, _mempool_a) = start_sequencer(config_a.clone()).await;
    seq_a.run_production_turn().await.unwrap();
    let tip_a = seq_a
        .block_store()
        .latest_block_meta()
        .await
        .unwrap()
        .unwrap();
    let messages = channel_from_store(seq_a.block_store(), 10).await;
    let tip_slot = messages.last().unwrap().1.lib_slot;

    // Sequencer B adopted a competitor at that height and never saw it finalize.
    let (seq_b, mempool_b) = start_sequencer(setup_sequencer_config()).await;
    let genesis_b = seq_b
        .block_store()
        .latest_block_meta()
        .await
        .unwrap()
        .unwrap();
    let competitor =
        common::test_utils::produce_dummy_block(tip_a.id, Some(genesis_b.hash), vec![]);
    assert_ne!(competitor.header.hash, tip_a.hash);
    apply_follow_update(
        seq_b.block_store().storage_ref(),
        &seq_b.chain(),
        &mempool_b,
        FollowUpdate {
            adopted: vec![(MsgId::from([7_u8; 32]), competitor)],
            ..empty_follow_update()
        },
    )
    .await;
    assert_eq!(
        seq_b
            .block_store()
            .latest_block_meta()
            .await
            .unwrap()
            .unwrap()
            .id,
        tip_a.id,
        "the competitor is the head tip going in"
    );

    let mock_b = MockBlockPublisher::with_canned_channel(
        config_a.bedrock_config.channel_id,
        Some(tip_slot),
        messages,
    );
    SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(
        &mock_b,
        &seq_b.store,
        &seq_b.chain,
        true,
    )
    .await
    .expect("finalized history must replace a conflicting head block");

    let tip_b = seq_b
        .block_store()
        .latest_block_meta()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tip_b.id, tip_a.id);
    assert_eq!(
        tip_b.hash, tip_a.hash,
        "the finalized block replaces the head competitor"
    );
}

/// A sequencer config whose genesis funds the bridge account, so replayed bridge
/// deposit transactions have a source balance to mint from.
fn bridge_funded_config() -> SequencerConfig {
    let mut config = setup_sequencer_config();
    config.genesis = vec![GenesisAction::SupplyBridgeAccount { balance: 1_000_000 }];
    config
}

/// Builds an unfulfilled pending deposit event for `recipient`, matching the
/// encoding `build_bridge_deposit_tx_from_event` expects.
fn deposit_event_record(
    op_id: [u8; 32],
    amount: u64,
    recipient: lee::AccountId,
) -> PendingDepositEventRecord {
    PendingDepositEventRecord {
        deposit_op_id: HashType(op_id),
        source_tx_hash: HashType([0_u8; 32]),
        amount,
        metadata: borsh::to_vec(&DepositMetadataForEncoding {
            recipient_id: recipient,
        })
        .unwrap(),
    }
}

/// Builds a signed public bridge `Withdraw` transaction (the normal user path).
fn build_public_withdraw_tx(
    sender: lee::AccountId,
    nonce: u128,
    amount: u64,
    bedrock_account_pk: [u8; 32],
    signing_key: &lee::PrivateKey,
) -> LeeTransaction {
    let message = lee::public_transaction::Message::try_new(
        programs::bridge().id(),
        vec![sender, system_accounts::bridge_account_id()],
        vec![nonce.into()],
        bridge_core::Instruction::Withdraw {
            amount,
            bedrock_account_pk,
        },
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[signing_key]);
    LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set))
}

/// The reconciliation key a produced block carries for `withdraw_tx`, keyed on
/// the note [`MockBlockPublisher`] reports as released for it.
fn produced_withdraw_key(withdraw_tx: &LeeTransaction) -> WithdrawalReconciliationKey {
    let withdraw_arg = crate::extract_bridge_withdraw_data(withdraw_tx).expect("withdraw data");
    let [note_id] = crate::mock::mock_released_notes(std::slice::from_ref(&withdraw_arg))[..]
    else {
        panic!("A bridge withdraw releases exactly one note");
    };

    crate::withdrawal_reconciliation_key(&note_id)
}

/// Cold-start backfill re-records an already-finalized deposit event as a
/// pending record before reconstruction replays the same deposit block.
/// Reconstruction must drop that record — its mint is permanently reflected in
/// the reconstructed state (the receipt PDA) — so the next production neither
/// re-mints the vault nor emits a stray deposit tx.
#[tokio::test]
async fn reconstructed_deposit_is_not_reminted_after_backfill_redelivery() {
    let recipient = initial_public_user_accounts()[0].account_id;
    let deposit_amount = 500_u64;
    let withdraw_amount = 100_u64;
    let bedrock_account_pk = [0x22_u8; 32];
    let deposit_op_id = [0x0d_u8; 32];

    // Sequencer A produces a deposit block then a withdraw block.
    let config_a = bridge_funded_config();

    let storage = StorageActor::new(&config_a.db_path()).expect("Failed to open database");
    let storage_ref = StorageActor::spawn(storage);

    let (mut seq_a, mempool_a) =
        SequencerCoreWithMockClients::start_from_config(config_a.clone(), storage_ref).await;

    let deposit_record = deposit_event_record(deposit_op_id, deposit_amount, recipient);
    let deposit_tx =
        crate::build_bridge_deposit_tx_from_event(&deposit_record).expect("build deposit tx");
    mempool_a
        .push((TransactionOrigin::Sequencer, deposit_tx))
        .await
        .unwrap();
    seq_a.run_production_turn().await.unwrap();

    let withdraw_tx = build_public_withdraw_tx(
        recipient,
        0,
        withdraw_amount,
        bedrock_account_pk,
        &create_signing_key_for_account1(),
    );
    mempool_a
        .push((TransactionOrigin::User, withdraw_tx.clone()))
        .await
        .unwrap();
    seq_a.run_production_turn().await.unwrap();

    let tip_a = seq_a
        .block_store()
        .latest_block_meta()
        .await
        .unwrap()
        .unwrap();
    let messages = channel_from_store(seq_a.block_store(), 10).await;
    let tip_slot = messages.last().unwrap().1.lib_slot;
    let channel_id = config_a.bedrock_config.channel_id;

    let config_b = bridge_funded_config();

    let storage = StorageActor::new(&config_b.db_path()).expect("Failed to open database");
    let storage_ref = StorageActor::spawn(storage);

    let (mut seq_b, _mempool_b) =
        SequencerCoreWithMockClients::start_from_config(config_b, storage_ref).await;

    // Backfill re-delivery: the deposit event is re-recorded as a pending record
    // before reconstruction runs. The mint no longer flows through the mempool
    // (that sink was removed); the store drain is the only source.
    assert!(
        seq_b
            .block_store()
            .storage_ref()
            .ask(AddPendingDepositEvent {
                event: deposit_record.clone()
            })
            .await
            .unwrap()
    );

    let mock_b = MockBlockPublisher::with_canned_channel(channel_id, Some(tip_slot), messages);
    SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(
        &mock_b,
        &seq_b.store,
        &seq_b.chain,
        true,
    )
    .await
    .expect("reconstruct");

    let tip_b = seq_b
        .block_store()
        .latest_block_meta()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tip_b.id, tip_a.id);
    assert_eq!(tip_b.hash, tip_a.hash);

    // Reconstruction replays the finalized deposit block, minting the receipt
    // into state and dropping the re-recorded pending event — so the drain has
    // nothing left to re-mint. This is the mechanism that protects against the
    // re-delivery, in place of the removed mempool sink.
    assert!(
        seq_b
            .block_store()
            .storage_ref()
            .ask(GetPendingDepositEvents {})
            .await
            .unwrap()
            .is_empty(),
        "reconstruction must drop the re-delivered pending deposit record"
    );

    seq_b.run_production_turn().await.unwrap();

    let vault_id = vault_core::compute_vault_account_id(programs::vault().id(), recipient);
    let bridge_id = system_accounts::bridge_account_id();
    let state_b = seq_b.chain().lock().await.head_state().clone();
    let state_a = seq_a.chain().lock().await.head_state().clone();
    for account in [vault_id, bridge_id, recipient] {
        assert_eq!(
            state_b.get_account_by_id(account).balance,
            state_a.get_account_by_id(account).balance,
            "reconstructed balance mismatch for {account:?}",
        );
    }
    assert_eq!(
        state_b.get_account_by_id(vault_id).balance,
        u128::from(deposit_amount),
        "deposit must mint into the recipient vault exactly once, not twice"
    );

    let produced = seq_b
        .block_store()
        .block_at_id(tip_b.id + 1)
        .await
        .unwrap()
        .expect("produced block present");
    assert!(
        !produced
            .body
            .transactions
            .iter()
            .any(|tx| crate::extract_bridge_deposit_id(tx) == Some(HashType(deposit_op_id))),
        "the re-delivered mint must be skipped, not re-included in a block"
    );

    // A reconstructed withdraw's finalized L1 event was already re-delivered (and
    // dropped) by cold-start backfill, so it will never be consumed again.
    // Reconstruction must not count it, or the count stays phantom-inflated forever.
    let key = produced_withdraw_key(&withdraw_tx);
    assert!(
        !seq_b
            .block_store()
            .storage_ref()
            .ask(ConsumeUnseenWithdrawCount { withdrawal: key })
            .await
            .unwrap(),
        "reconstruction must not leave a phantom unseen-withdraw count"
    );
}

/// A reconstructed withdraw block must not touch the unseen-withdraw counter.
/// Its finalized L1 Withdraw event was already re-delivered (and dropped as a
/// no-op) by cold-start backfill, so counting it during reconstruction would
/// leave a permanent phantom that nothing ever consumes.
#[tokio::test]
async fn reconstructed_withdraw_leaves_no_phantom_unseen_count() {
    let recipient = initial_public_user_accounts()[0].account_id;
    let withdraw_amount = 100_u64;
    let bedrock_account_pk = [0x33_u8; 32];

    // Sequencer A produces a single withdraw block; treat its chain as the channel.
    let config_a = bridge_funded_config();

    let storage = StorageActor::new(&config_a.db_path()).expect("Failed to open database");
    let storage_ref = StorageActor::spawn(storage);

    let (mut seq_a, mempool_a) =
        SequencerCoreWithMockClients::start_from_config(config_a.clone(), storage_ref).await;
    let withdraw_tx = build_public_withdraw_tx(
        recipient,
        0,
        withdraw_amount,
        bedrock_account_pk,
        &create_signing_key_for_account1(),
    );
    mempool_a
        .push((TransactionOrigin::User, withdraw_tx.clone()))
        .await
        .unwrap();
    seq_a.run_production_turn().await.unwrap();

    let key = produced_withdraw_key(&withdraw_tx);
    // Producing the withdraw counts it as unseen, awaiting its L1 event.
    assert!(
        seq_a
            .block_store()
            .storage_ref()
            .ask(ConsumeUnseenWithdrawCount { withdrawal: key })
            .await
            .unwrap(),
        "producing a withdraw must count it as unseen"
    );

    let messages = channel_from_store(seq_a.block_store(), 10).await;
    let tip_slot = messages.last().unwrap().1.lib_slot;
    let channel_id = config_a.bedrock_config.channel_id;

    // Sequencer B reconstructs A's chain from a fresh store.
    let config_b = bridge_funded_config();
    let (store_b, chain_b) = fresh_store_and_chain(&config_b).await;
    let mock_b = MockBlockPublisher::with_canned_channel(channel_id, Some(tip_slot), messages);
    SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(&mock_b, &store_b, &chain_b, true)
        .await
        .expect("reconstruct");

    assert!(
        !store_b
            .storage_ref()
            .ask(ConsumeUnseenWithdrawCount { withdrawal: key })
            .await
            .unwrap(),
        "reconstruction must not leave a phantom unseen-withdraw count"
    );
}

/// A deposit whose L1 event was observed (an unfulfilled pending record
/// exists) and whose L2 mint is already contained in a finalized channel block.
/// Reconstruction must reconcile the pending record against that block — marking
/// it submitted so the startup replay does not re-inject it — and apply the mint
/// exactly once.
#[tokio::test]
async fn reconstruction_reconciles_already_finished_deposit() {
    let recipient = initial_public_user_accounts()[0].account_id;
    let deposit_amount = 400_u64;
    let deposit_op_id = [0x1a_u8; 32];

    // Sequencer A: a single block that fully processes the bridge deposit.
    let config_a = bridge_funded_config();
    let (mut seq_a, mempool_a) = start_sequencer(config_a.clone()).await;
    let deposit_record = deposit_event_record(deposit_op_id, deposit_amount, recipient);
    let deposit_tx =
        crate::build_bridge_deposit_tx_from_event(&deposit_record).expect("build deposit tx");
    mempool_a
        .push((TransactionOrigin::Sequencer, deposit_tx))
        .await
        .unwrap();
    seq_a.run_production_turn().await.unwrap();

    let messages = channel_from_store(seq_a.block_store(), 10).await;
    let tip_slot = messages.last().unwrap().1.lib_slot;
    let channel_id = config_a.bedrock_config.channel_id;

    // Sequencer B: fresh store, but with the *unfulfilled* pending deposit event
    // pre-seeded, as the cold-start backfill would when it re-observes this
    // already-finalized deposit.
    let config_b = bridge_funded_config();
    let (store_b, chain_b) = fresh_store_and_chain(&config_b).await;
    assert!(
        store_b
            .storage_ref()
            .ask(AddPendingDepositEvent {
                event: deposit_record.clone()
            })
            .await
            .unwrap()
    );

    let mock_b = MockBlockPublisher::with_canned_channel(channel_id, Some(tip_slot), messages);
    SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(&mock_b, &store_b, &chain_b, true)
        .await
        .expect("reconstruct");

    // The mint was applied exactly once.
    let vault_id = vault_core::compute_vault_account_id(programs::vault().id(), recipient);
    assert_eq!(
        chain_b
            .lock()
            .await
            .head_state()
            .get_account_by_id(vault_id)
            .balance,
        u128::from(deposit_amount),
        "already-finished deposit must be applied exactly once"
    );

    // The mint's receipt PDA is in the reconstructed state, and reconstruction
    // dropped the pending record backfill had re-delivered — so the production
    // drain sees the deposit as minted and never re-emits it.
    assert!(
        crate::deposit_already_minted(chain_b.lock().await.head_state(), HashType(deposit_op_id)),
        "the reconstructed deposit's receipt marks it minted"
    );
    assert!(
        store_b
            .get_pending_deposit_events()
            .await
            .unwrap()
            .is_empty(),
        "reconstruction drops the finalized deposit's pending record"
    );
}

/// A cross-zone delivery whose record is still pending locally, but whose block
/// arrives already finalized on the channel. Reconstruction must settle the
/// record on the way through: the delivery is permanently reflected in the
/// reconstructed state (the inbox seen shard), so the next production neither
/// re-delivers it nor leaves a record nothing will ever drop.
#[tokio::test]
async fn reconstructed_delivery_settles_its_pending_record() {
    let payload = b"reconstructed".to_vec();
    let record = dispatch_record(23, ping_payload(&payload));
    let key = record.message_key;

    // Sequencer A produces the block that carries the delivery.
    let config_a = cross_zone_test_config();
    let (mut seq_a, _mempool_a) = start_sequencer(config_a.clone()).await;
    seq_a
        .block_store()
        .storage_ref()
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![record.clone()],
        })
        .await
        .unwrap();
    seq_a.run_production_turn().await.unwrap();

    let tip_a = seq_a
        .block_store()
        .latest_block_meta()
        .await
        .unwrap()
        .unwrap();
    let messages = channel_from_store(seq_a.block_store(), 10).await;
    let tip_slot = messages.last().unwrap().1.lib_slot;
    let channel_id = config_a.bedrock_config.channel_id;

    // Sequencer B holds the same record, as its own watcher would after reading
    // the peer block, and reconstructs A's chain from a fresh store.
    let (mut seq_b, _mempool_b) = start_sequencer(cross_zone_test_config()).await;
    assert_eq!(
        seq_b
            .block_store()
            .storage_ref()
            .ask(AddPendingCrossZoneDispatches {
                dispatches: vec![record],
            })
            .await
            .unwrap(),
        1
    );

    let mock_b = MockBlockPublisher::with_canned_channel(channel_id, Some(tip_slot), messages);
    SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(
        &mock_b,
        &seq_b.store,
        &seq_b.chain,
        true,
    )
    .await
    .expect("reconstruct");

    let tip_b = seq_b
        .block_store()
        .latest_block_meta()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tip_b.id, tip_a.id);
    assert_eq!(tip_b.hash, tip_a.hash);
    assert!(
        seq_b
            .store
            .pending_cross_zone_dispatches()
            .await
            .unwrap()
            .is_empty(),
        "reconstruction must settle the record of a delivery it replayed"
    );

    // The delivery landed exactly once, and the next turn does not re-emit it.
    let record_id = ping_record_pda(programs::ping_receiver().id());
    assert_eq!(
        seq_b
            .with_state(|state| state.get_account_by_id(record_id).data.into_inner())
            .await,
        payload,
        "the reconstructed delivery must reach its target program"
    );
    seq_b.run_production_turn().await.unwrap();
    let produced = seq_b
        .block_store()
        .block_at_id(tip_b.id + 1)
        .await
        .unwrap()
        .expect("produced block present");
    assert!(
        !dispatches_in(&produced).contains(&key),
        "the reconstructed delivery must not be re-emitted"
    );
}

/// A delivery this node published itself, served back by the channel at or below
/// its own tip. That path verifies the block matches and returns early, so it is
/// reached on every restart. It must still settle the delivery's record: the
/// channel serving the block is what makes it irreversible, and nothing later
/// will ever put that key in a block again.
#[tokio::test]
async fn a_verified_own_block_settles_its_delivery_records() {
    let record = dispatch_record(37, ping_payload(b"verified"));
    let key = record.message_key;

    let (mut seq, _mempool) = start_sequencer(cross_zone_test_config()).await;
    seq.block_store()
        .storage_ref()
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![record],
        })
        .await
        .unwrap();

    let block_id = seq.run_production_turn().await.unwrap();
    let block = seq
        .block_store()
        .block_at_id(block_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dispatches_in(&block), vec![key]);
    assert_eq!(
        seq.store
            .pending_cross_zone_dispatches()
            .await
            .unwrap()
            .len(),
        1,
        "producing the block is not what settles the record"
    );

    // The channel serves our own chain back, tip included.
    let messages = channel_from_store(seq.block_store(), 10).await;
    let tip_slot = messages.last().unwrap().1.lib_slot;
    let mock = MockBlockPublisher::with_canned_channel(
        seq.sequencer_config.bedrock_config.channel_id,
        Some(tip_slot),
        messages,
    );
    SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(
        &mock, &seq.store, &seq.chain, true,
    )
    .await
    .expect("reconstruct");

    assert!(
        seq.store
            .pending_cross_zone_dispatches()
            .await
            .unwrap()
            .is_empty(),
        "a delivery the channel confirms must not leave a record nothing can remove"
    );
}

#[tokio::test]
async fn committed_local_against_missing_channel_fails_without_anchor() {
    // A sequencer that has committed blocks — a non-genesis tip plus a persisted
    // checkpoint — but only ever produced (so it never recorded a per-block
    // anchor). Restarting it against a wiped/missing channel must still fail,
    // driven by the committed-blocks invariant rather than an anchor probe.
    let config = setup_sequencer_config();
    let storage_weak = {
        let (mut seq, _handle) = start_sequencer(config.clone()).await;
        seq.run_production_turn().await.unwrap();
        seq.run_production_turn().await.unwrap();
        assert!(
            seq.block_store()
                .latest_block_meta()
                .await
                .unwrap()
                .unwrap()
                .id
                > 1
        );
        seq.block_store().storage_ref().downgrade()
    };
    storage_weak.wait_for_shutdown_with_result(|_| ()).await;

    // Reopen: blocks beyond genesis, no anchor. `is_fresh_start = false` stands in
    // for a checkpoint persisted by a prior sync (the mock never emits one).
    let (store, chain) = fresh_store_and_chain(&config).await;
    assert!(store.get_zone_anchor().await.unwrap().is_none());
    assert!(store.latest_block_meta().await.unwrap().unwrap().id > 1);

    // The channel is gone: no tip, no messages.
    let mock =
        MockBlockPublisher::with_canned_channel(config.bedrock_config.channel_id, None, vec![]);
    let result =
        SequencerCore::<MockBlockPublisher>::verify_and_reconstruct(&mock, &store, &chain, false)
            .await;
    assert!(
        result.is_err(),
        "committed blocks against a missing channel must abort startup"
    );
}
