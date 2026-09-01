#![expect(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use std::{pin::pin, sync::Arc, time::Duration};

use common::{
    HashType,
    block::{BedrockStatus, Block, HashableBlockData},
    test_utils::sequencer_sign_key_for_testing,
    transaction::{LeeTransaction, clock_invocation},
};
use kameo::actor::Spawn as _;
use lee::{
    Account, AccountId, PrivateKey, PublicKey, PublicTransaction, V03State, program::Program,
};
use lee_core::account::Nonce;
use logos_blockchain_core::{
    events::DepositRecreatedNotes,
    mantle::{
        TxHash,
        ledger::Inputs,
        ops::channel::{ChannelId, MsgId, deposit::Metadata},
    },
};
use logos_blockchain_key_management_system_service::keys::{Ed25519Key, ZkPublicKey};
use logos_blockchain_zone_sdk::{Slot, sequencer::DepositInfo};
use mempool::MemPoolHandle;
use ping_core::{ReceiverInstruction, ping_record_pda, receiver_config_account_id};
use sequencer_storage_actor::{
    StorageActor,
    protocol::{
        AddPendingCrossZoneDispatches, AddPendingDepositEvent, DispatchOrigin,
        PendingCrossZoneDispatchRecord, PendingDepositEventRecord, RecordNewBlock,
    },
};
use tempfile::tempdir;
use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};

use crate::{
    LiveCommittee, MAX_DISPATCHES_PER_BLOCK, RETIRE_DISPATCH_AFTER_FAILURES, TransactionOrigin,
    apply_follow_update,
    block_publisher::FollowUpdate,
    build_bridge_deposit_tx_from_event, build_finalize_unstake_tx, build_genesis_state,
    classify_settled_deliveries,
    config::{
        self, BedrockConfig, CrossZoneConfig, CrossZonePeer, CrossZoneRoute, GenesisAction,
        SequencerConfig,
    },
    deposit_already_minted, dispatch_already_delivered, extract_cross_zone_dispatch,
    extract_cross_zone_dispatch_key, finalize_unstake_is_includable, is_sequencer_only_program,
    mock::{SequencerCoreWithMockClients, checkpoint_at, mock_checkpoint, mock_msg_of},
    resubmittable_txs,
};

mod reconstruction;

/// The peer zone a cross-zone test receives from. Distinct from the test
/// channel id (`[0; 32]`), which the inbox guest rejects as a source.
const PEER_ZONE: [u8; 32] = [0xbe_u8; 32];

/// The inscription a test slash names; only has to match the approvals.
const TEST_INSCRIPTION: [u8; 32] = [0xA1; 32];

#[derive(borsh::BorshSerialize)]
struct DepositMetadataForEncoding {
    recipient_id: lee::AccountId,
}

/// The bootstrap sequencer's key for `config`, exactly as `start_from_config`
/// would derive it: read from `config.home`'s key file if present, else
/// generated and persisted there. Callers building genesis state by hand (or
/// reopening a store `start_from_config` already created) must use this
/// rather than a fixed constant, so it always matches what's actually on
/// disk.
fn test_bootstrap_sequencer_key(config: &SequencerConfig) -> sequencer_stake_core::SequencerKey {
    let bytes = crate::load_or_create_signing_key(&config.home.join("bedrock_signing_key"))
        .expect("Failed to load or create bedrock signing key")
        .public_key()
        .to_bytes();
    sequencer_stake_core::SequencerKey::new(bytes)
        .expect("a Bedrock public key is a valid Ed25519 public key")
}

fn test_sequencer_key(seed: u8) -> sequencer_stake_core::SequencerKey {
    let bytes = Ed25519Key::from_bytes(&[seed; 32]).public_key().to_bytes();
    sequencer_stake_core::SequencerKey::new(bytes)
        .expect("a Bedrock public key is a valid Ed25519 public key")
}

async fn start_sequencer(
    config: SequencerConfig,
) -> (
    SequencerCoreWithMockClients,
    MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
) {
    let storage = StorageActor::new(&config.db_path()).expect("Failed to open database");
    let storage_ref = StorageActor::spawn(storage);
    SequencerCoreWithMockClients::start_from_config(config, storage_ref).await
}

/// A follow update carrying nothing, to fill in the fields a test does not
/// exercise via `..empty_follow_update()`.
fn empty_follow_update() -> FollowUpdate {
    FollowUpdate {
        checkpoint: mock_checkpoint(),
        adopted: Vec::new(),
        orphaned: Vec::new(),
        finalized: Vec::new(),
        deposits: Vec::new(),
        withdrawals: Vec::new(),
        undecodable: Vec::new(),
    }
}

/// Key of the account holding a solo channel creator's genesis stake. Read
/// from the same file genesis uses, which creates it on first read.
fn bootstrap_stake_key(config: &SequencerConfig) -> PrivateKey {
    crate::load_or_create_stake_signing_key(&config.home.join("sequencer_stake_signing_key"))
        .expect("Failed to load or create the stake signing key")
}

fn bootstrap_stake_account_id(config: &SequencerConfig) -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(&bootstrap_stake_key(
        config,
    )))
}

fn setup_sequencer_config() -> SequencerConfig {
    let tempdir = tempfile::tempdir().unwrap();
    let home = tempdir.path().to_path_buf();

    SequencerConfig {
        home,
        max_num_tx_in_block: 10,
        max_block_size: bytesize::ByteSize::mib(1),
        mempool_max_size: 10000,
        block_create_timeout: Duration::from_secs(1),
        signing_key: *sequencer_sign_key_for_testing().value(),
        bedrock_config: BedrockConfig {
            channel_id: ChannelId::from([0; 32]),
            node_url: "http://not-used-in-unit-tests".parse().unwrap(),
            auth: None,
            funding_key: ZkPublicKey::zero(),
            priority_fee_percent: config::default_priority_fee_percent(),
        },
        retry_pending_blocks_timeout: Duration::from_mins(4),
        genesis: vec![],
        cross_zone: None,
        metrics_address: None,
        gossip: None,
    }
}

#[test]
fn only_the_cross_zone_inbox_is_sequencer_only() {
    assert!(is_sequencer_only_program(programs::cross_zone_inbox().id()));
    assert!(!is_sequencer_only_program(
        programs::cross_zone_outbox().id()
    ));
    assert!(!is_sequencer_only_program(programs::wrapped_token().id()));
    assert!(!is_sequencer_only_program(programs::ping_sender().id()));
    assert!(!is_sequencer_only_program(programs::clock().id()));
}

#[test]
fn committee_cooldown_needs_the_channel_to_advance() {
    type Core = SequencerCoreWithMockClients;
    let cooldown = Core::COMMITTEE_SUBMISSION_COOLDOWN;
    let submitted_at = Slot::new(100);

    assert!(Core::committee_cooldown_elapsed(None, None));
    assert!(!Core::committee_cooldown_elapsed(Some(submitted_at), None));
    assert!(!Core::committee_cooldown_elapsed(
        Some(submitted_at),
        Some(Slot::new(100 + cooldown - 1))
    ));
    assert!(Core::committee_cooldown_elapsed(
        Some(submitted_at),
        Some(Slot::new(100 + cooldown))
    ));
}

fn create_signing_key_for_account1() -> lee::PrivateKey {
    initial_pub_accounts_private_keys()[0].pub_sign_key.clone()
}

fn create_signing_key_for_account2() -> lee::PrivateKey {
    initial_pub_accounts_private_keys()[1].pub_sign_key.clone()
}

async fn common_setup() -> (
    SequencerCoreWithMockClients,
    MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
) {
    let config = setup_sequencer_config();
    common_setup_with_config(config).await
}

async fn common_setup_with_config(
    config: SequencerConfig,
) -> (
    SequencerCoreWithMockClients,
    MemPoolHandle<(TransactionOrigin, LeeTransaction)>,
) {
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    let tx = common::test_utils::produce_dummy_empty_transaction();
    mempool_handle
        .push((TransactionOrigin::User, tx))
        .await
        .unwrap();

    sequencer.run_production_turn().await.unwrap();

    (sequencer, mempool_handle)
}

fn tx_is_bridge_deposit(
    tx: &LeeTransaction,
    deposit_op_id: [u8; 32],
    expected_amount: u64,
) -> bool {
    let LeeTransaction::Public(public_tx) = tx else {
        return false;
    };

    if public_tx.message.program_id != programs::bridge().id() {
        return false;
    }

    let instruction: bridge_core::Instruction =
        match borsh::from_slice(&public_tx.message.instruction_data) {
            Ok(instruction) => instruction,
            Err(_err) => return false,
        };

    matches!(
        instruction,
        bridge_core::Instruction::Deposit {
            l1_deposit_op_id,
            amount,
            ..
        } if l1_deposit_op_id == deposit_op_id && amount == expected_amount
    )
}

/// A config that receives `ping_receiver` messages from [`PEER_ZONE`], so
/// `build_genesis_state` seeds the inbox config PDA and a delivery has an
/// allowlist to pass.
fn cross_zone_test_config() -> SequencerConfig {
    SequencerConfig {
        cross_zone: Some(CrossZoneConfig {
            peers: vec![CrossZonePeer {
                channel_id: PEER_ZONE,
                allowed_routes: vec![CrossZoneRoute {
                    src_program_id: programs::ping_sender().id(),
                    target_program_id: programs::ping_receiver().id(),
                    mint_cap: None,
                }],
                expected_block_signing_pubkeys: Vec::new(),
                min_committee_size: 0,
            }],
            source_authority: None,
            source_governance: None,
        }),
        ..setup_sequencer_config()
    }
}

/// A `ping_receiver::Record` instruction: the wire form an emitter on the peer
/// zone puts in the message payload.
fn ping_payload(payload: &[u8]) -> Vec<u8> {
    borsh::to_vec(&ReceiverInstruction::Record {
        payload: payload.to_vec(),
    })
    .expect("ping instruction serializes")
}

/// The dispatch transaction for a message at index 0 of [`PEER_ZONE`] block
/// `src_block_id`. Built through the same builder the watcher uses, so a change
/// to the encoding shows up here rather than passing silently.
fn dispatch_tx(src_block_id: u64, payload: Vec<u8>) -> LeeTransaction {
    let receiver_id = programs::ping_receiver().id();
    LeeTransaction::Public(cross_zone::build_dispatch_from_emission(
        &cross_zone::EmissionSource {
            src_zone: PEER_ZONE,
            src_block_id,
            src_block_hash: peer_block_hash(src_block_id),
            src_tx_index: 0,
            src_program_id: programs::ping_sender().id(),
        },
        receiver_id,
        &[
            receiver_config_account_id(receiver_id).into_value(),
            ping_record_pda(receiver_id).into_value(),
        ],
        payload,
    ))
}

/// A stand-in for the peer block's recomputed hash, distinct per block id. These
/// records are seeded into the store, so no real block exists to hash.
fn peer_block_hash(src_block_id: u64) -> [u8; 32] {
    let mut hash = [0_u8; 32];
    hash[..8].copy_from_slice(&src_block_id.to_le_bytes());
    hash
}

/// The pending record the watcher would leave behind for that dispatch.
fn dispatch_record(src_block_id: u64, payload: Vec<u8>) -> PendingCrossZoneDispatchRecord {
    let tx = dispatch_tx(src_block_id, payload);
    PendingCrossZoneDispatchRecord::recorded(
        cross_zone_inbox_core::message_key(&PEER_ZONE, src_block_id, 0),
        borsh::to_vec(&tx).expect("dispatch encodes"),
    )
}

/// The message keys of the deliveries a block carries.
fn dispatches_in(block: &Block) -> Vec<[u8; 32]> {
    block
        .body
        .transactions
        .iter()
        .filter_map(extract_cross_zone_dispatch_key)
        .collect()
}

/// The pending dispatch records a sequencer still holds.
async fn pending_dispatches(
    sequencer: &SequencerCoreWithMockClients,
) -> Vec<PendingCrossZoneDispatchRecord> {
    sequencer
        .block_store()
        .pending_cross_zone_dispatches()
        .await
        .expect("pending dispatches readable")
}

#[tokio::test]
async fn start_from_config() {
    let config = setup_sequencer_config();
    let (sequencer, _mempool_handle) = start_sequencer(config.clone()).await;

    assert_eq!(sequencer.chain_height().await, 1);
    assert_eq!(sequencer.sequencer_config.max_num_tx_in_block, 10);

    let acc1_account_id = initial_public_user_accounts()[0].account_id;
    let acc2_account_id = initial_public_user_accounts()[1].account_id;

    let balance_acc_1 = sequencer
        .with_state(|s| s.get_account_by_id(acc1_account_id).balance)
        .await;
    let balance_acc_2 = sequencer
        .with_state(|s| s.get_account_by_id(acc2_account_id).balance)
        .await;

    assert_eq!(10000, balance_acc_1);
    assert_eq!(20000, balance_acc_2);
}

#[tokio::test]
async fn start_from_config_opens_existing_db_if_it_exists() {
    let config = setup_sequencer_config();
    let temp_dir = tempdir().unwrap();
    let mut config = config;
    config.home = temp_dir.path().to_path_buf();

    let bootstrap_sequencer_key = test_bootstrap_sequencer_key(&config);
    let signing_key = lee::PrivateKey::try_new(config.signing_key).unwrap();
    let (genesis_state, genesis_txs) = build_genesis_state(&config, Some(bootstrap_sequencer_key));
    let genesis_hashable_data = HashableBlockData {
        block_id: 1,
        transactions: genesis_txs,
        prev_block_hash: HashType([0; 32]),
        timestamp: 0,
    };
    let genesis_block = genesis_hashable_data.into_pending_block(&signing_key);

    let storage = StorageActor::new(&config.db_path()).unwrap();
    let storage_ref = StorageActor::spawn(storage);
    storage_ref
        .ask(RecordNewBlock {
            block: genesis_block,
            channel_cursor: None,
            withdrawals: vec![],
            state: Arc::new(genesis_state),
            checkpoint_bytes: None,
        })
        .await
        .unwrap();
    storage_ref.stop_gracefully().await.unwrap();
    storage_ref.wait_for_shutdown().await;

    let (sequencer, _mempool_handle) = start_sequencer(config).await;
    assert_eq!(sequencer.chain_height().await, 1);
    assert!(sequencer.store.last_block_id().await.is_ok());
}

#[should_panic(expected = "Failed to open database")]
#[tokio::test]
async fn start_from_config_panics_when_db_open_returns_non_not_found_error() {
    let mut config = setup_sequencer_config();
    let temp_dir = tempdir().unwrap();
    config.home = temp_dir.path().to_path_buf();

    let db_path = config.db_path();

    std::fs::create_dir_all(&config.home).unwrap();
    // Force RocksDB open to fail with an IO error by placing a file at DB path.
    std::fs::write(&db_path, b"not-a-directory").unwrap();

    let _ = start_sequencer(config).await;
}

#[tokio::test]
async fn unfulfilled_deposit_events_are_drained_from_the_store_on_production() {
    let mut config = setup_sequencer_config();
    // The mint moves funds out of the bridge account, so it has to hold some.
    config.genesis = vec![GenesisAction::SupplyBridgeAccount { balance: 1_000_000 }];
    let deposit_op_id = [13_u8; 32];
    let expected_amount = 1_u64;
    let recipient_id = initial_public_user_accounts()[0].account_id;

    let storage_weak = {
        let (sequencer, _mempool_handle) = start_sequencer(config.clone()).await;
        sequencer.block_store().storage_ref().downgrade()
    };
    storage_weak.wait_for_shutdown_with_result(|_| ()).await;

    let pending_event = PendingDepositEventRecord {
        deposit_op_id: HashType(deposit_op_id),
        source_tx_hash: HashType([7_u8; 32]),
        amount: expected_amount,
        metadata: borsh::to_vec(&DepositMetadataForEncoding { recipient_id }).unwrap(),
    };

    {
        let storage_ref = StorageActor::spawn(StorageActor::new(&config.db_path()).unwrap());
        let inserted = storage_ref
            .ask(AddPendingDepositEvent {
                event: pending_event,
            })
            .await
            .unwrap();
        assert!(inserted);
        storage_ref.stop_gracefully().await.unwrap();
        storage_ref.wait_for_shutdown().await;
    }

    // The mint never goes through the mempool: the record is the queue, and
    // production drains it. That is what makes a restart — or a follow event
    // arriving while a full mempool would have dropped the push — lossless.
    let (mut sequencer, _mempool_handle) = start_sequencer(config).await;
    assert!(
        sequencer.mempool.pop().is_none(),
        "deposit mints are drained from the store, never queued in the mempool"
    );

    let block_id = sequencer.run_production_turn().await.unwrap();
    let block = sequencer
        .store
        .block_at_id(block_id)
        .await
        .unwrap()
        .expect("produced block is stored");
    assert!(
        block
            .body
            .transactions
            .iter()
            .any(|tx| tx_is_bridge_deposit(tx, deposit_op_id, expected_amount)),
        "the drained deposit mint should be included in the produced block"
    );

    // The record stays until its deposit finalizes; exactly-once is enforced by
    // the receipt PDA now in head state, not by any marker on the record.
    assert!(
        sequencer
            .store
            .get_pending_deposit_events()
            .await
            .unwrap()
            .iter()
            .any(|event| event.deposit_op_id == HashType(deposit_op_id)),
        "the record remains until the deposit finalizes"
    );
    assert!(
        sequencer
            .with_state(|state| deposit_already_minted(state, HashType(deposit_op_id)))
            .await,
        "the deposit's receipt PDA marks it minted in head state"
    );
}

#[tokio::test]
async fn a_drained_deposit_is_not_minted_twice_across_turns() {
    let mut config = setup_sequencer_config();
    config.genesis = vec![GenesisAction::SupplyBridgeAccount { balance: 1_000_000 }];
    let deposit_op_id = [17_u8; 32];
    let recipient_id = initial_public_user_accounts()[0].account_id;

    let (mut sequencer, _mempool_handle) = start_sequencer(config).await;
    sequencer
        .block_store()
        .storage_ref()
        .ask(AddPendingDepositEvent {
            event: PendingDepositEventRecord {
                deposit_op_id: HashType(deposit_op_id),
                source_tx_hash: HashType([7_u8; 32]),
                amount: 1,
                metadata: borsh::to_vec(&DepositMetadataForEncoding { recipient_id }).unwrap(),
            },
        })
        .await
        .unwrap();

    let first = sequencer.run_production_turn().await.unwrap();
    let second = sequencer.run_production_turn().await.unwrap();

    let minted_in = async |block_id: u64| {
        sequencer
            .store
            .block_at_id(block_id)
            .await
            .unwrap()
            .expect("produced block is stored")
            .body
            .transactions
            .iter()
            .filter(|tx| tx_is_bridge_deposit(tx, deposit_op_id, 1))
            .count()
    };

    assert_eq!(minted_in(first).await, 1);
    assert_eq!(
        minted_in(second).await,
        0,
        "the receipt PDA from the first mint must keep the drain from re-minting"
    );
}

#[tokio::test]
async fn an_orphaned_deposit_is_reminted_exactly_once_in_the_replacement() {
    // Manifestation 2 from #639: a deposit-carrying block is orphaned. Recovery
    // rests entirely on the receipt PDA reverting with the block — no requeue,
    // no bookkeeping of our own — so the still-pending record is drained again
    // on the next turn and the vault is credited exactly once across the reorg.
    let mut config = setup_sequencer_config();
    config.genesis = vec![GenesisAction::SupplyBridgeAccount { balance: 1_000_000 }];
    let recipient_id = initial_public_user_accounts()[0].account_id;
    let deposit_op_id = [0x2c_u8; 32];
    let amount = 500_u64;

    let (mut sequencer, mempool_handle) = start_sequencer(config).await;
    sequencer
        .block_store()
        .storage_ref()
        .ask(AddPendingDepositEvent {
            event: PendingDepositEventRecord {
                deposit_op_id: HashType(deposit_op_id),
                source_tx_hash: HashType([7_u8; 32]),
                amount,
                metadata: borsh::to_vec(&DepositMetadataForEncoding { recipient_id }).unwrap(),
            },
        })
        .await
        .unwrap();

    // Produce the block that mints the deposit; its receipt marks it minted.
    sequencer.run_production_turn().await.unwrap();
    let minted_block = sequencer.store.block_at_id(2).await.unwrap().unwrap();
    assert!(
        sequencer
            .with_state(|s| deposit_already_minted(s, HashType(deposit_op_id)))
            .await,
        "the first mint claims the receipt in head state"
    );

    // Orphan that block. The receipt reverts with it — nothing else tracks the
    // mint — so the deposit reads as unminted again.
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            adopted: vec![],
            orphaned: vec![minted_block],
            ..empty_follow_update()
        },
    )
    .await;
    assert_eq!(
        sequencer.chain_height().await,
        1,
        "the minting block is orphaned"
    );
    assert!(
        !sequencer
            .with_state(|s| deposit_already_minted(s, HashType(deposit_op_id)))
            .await,
        "the receipt reverts with the orphaned block"
    );

    // Orphaning it takes the channel tip back with it.
    sequencer.block_publisher().set_channel_tip(None);

    // Next turn: the still-pending record is drained and re-minted on the new
    // head, exactly once.
    let replacement = sequencer.run_production_turn().await.unwrap();
    let mints = sequencer
        .store
        .block_at_id(replacement)
        .await
        .unwrap()
        .expect("replacement block is stored")
        .body
        .transactions
        .iter()
        .filter(|tx| tx_is_bridge_deposit(tx, deposit_op_id, amount))
        .count();
    assert_eq!(
        mints, 1,
        "the deposit is re-minted exactly once after the orphan"
    );
    let vault_id = vault_core::compute_vault_account_id(programs::vault().id(), recipient_id);
    assert_eq!(
        sequencer
            .with_state(|s| s.get_account_by_id(vault_id).balance)
            .await,
        u128::from(amount),
        "the vault is credited exactly once across the reorg"
    );
}

#[tokio::test]
async fn a_replayed_deposit_mint_no_ops_in_the_guest() {
    // Runs the bridge guest directly with a pre-existing receipt — the replay
    // no-op branch the exactly-once guarantee rests on. The store drain filters
    // duplicates out before the program executes, so this is the only test that
    // reaches that branch; applying the same mint twice asserts the second is a
    // no-op (credited once) rather than an error.
    let mut config = setup_sequencer_config();
    config.genesis = vec![GenesisAction::SupplyBridgeAccount { balance: 1_000_000 }];
    let recipient_id = initial_public_user_accounts()[0].account_id;
    let deposit_op_id = [0x5a_u8; 32];
    let amount = 500_u64;

    let (sequencer, _mempool_handle) = start_sequencer(config).await;

    let deposit_tx = build_bridge_deposit_tx_from_event(&PendingDepositEventRecord {
        deposit_op_id: HashType(deposit_op_id),
        source_tx_hash: HashType([7_u8; 32]),
        amount,
        metadata: borsh::to_vec(&DepositMetadataForEncoding { recipient_id }).unwrap(),
    })
    .unwrap();
    let LeeTransaction::Public(public_tx) = &deposit_tx else {
        panic!("bridge deposit tx is public");
    };

    let vault_id = vault_core::compute_vault_account_id(programs::vault().id(), recipient_id);
    let mut state = sequencer.chain().lock().await.head_state().clone();

    // First mint: claims the receipt and credits the recipient vault.
    state
        .transition_from_public_transaction(public_tx, 1, 0)
        .expect("first mint executes");
    assert_eq!(
        state.get_account_by_id(vault_id).balance,
        u128::from(amount)
    );
    assert!(
        deposit_already_minted(&state, HashType(deposit_op_id)),
        "the first mint claims the receipt PDA"
    );

    // Replay the identical mint. The guest sees the receipt already exists and
    // no-ops instead of failing, so the vault is credited exactly once.
    state
        .transition_from_public_transaction(public_tx, 2, 0)
        .expect("a replayed deposit is a no-op, not an error");
    assert_eq!(
        state.get_account_by_id(vault_id).balance,
        u128::from(amount),
        "a replayed deposit must not re-credit the vault"
    );
}

#[tokio::test]
async fn recorded_dispatches_are_drained_from_the_store_on_production() {
    let payload = b"hello-cross-zone".to_vec();
    let record = dispatch_record(7, ping_payload(&payload));
    let key = record.message_key;

    let (mut sequencer, _mempool_handle) = start_sequencer(cross_zone_test_config()).await;
    assert_eq!(
        sequencer
            .block_store()
            .storage_ref()
            .ask(AddPendingCrossZoneDispatches {
                dispatches: vec![record],
            })
            .await
            .unwrap(),
        1
    );

    // The delivery never goes through the mempool: the record is the queue, and
    // production drains it. That is what makes the window between the watcher's
    // durable read cursor and a block carrying the dispatch survivable, and
    // what lets a committee-floor suspension hold new reads without holding
    // deliveries already recorded: the watcher spawned here reads nothing (its
    // node URL is a dummy) and only ever records to the store, never the
    // mempool.
    assert!(
        sequencer.mempool.pop().is_none(),
        "deliveries are drained from the store, never queued in the mempool"
    );

    let block_id = sequencer.run_production_turn().await.unwrap();
    let block = sequencer
        .store
        .block_at_id(block_id)
        .await
        .unwrap()
        .expect("produced block is stored");
    assert_eq!(
        dispatches_in(&block),
        vec![key],
        "the drained delivery should be included in the produced block"
    );

    let record_id = ping_record_pda(programs::ping_receiver().id());
    assert_eq!(
        sequencer
            .with_state(|state| state.get_account_by_id(record_id).data.into_inner())
            .await,
        payload,
        "the dispatch must reach its target program, not just sit in the block"
    );

    // The record stays until the delivery finalizes; re-delivery is prevented by
    // the inbox seen-set now in head state, not by any marker on the record.
    assert_eq!(
        pending_dispatches(&sequencer)
            .await
            .iter()
            .map(|record| record.message_key)
            .collect::<Vec<_>>(),
        vec![key],
        "the record remains until the delivery becomes irreversible"
    );
}

#[tokio::test]
async fn a_delivered_dispatch_is_skipped_on_the_next_turn() {
    // The seen-set is what replaces the submitted mark: the drain asks the state
    // it is building on whether the inbox has already taken this message, so a
    // record that outlives its delivery costs one skipped drain, not a replay.
    let record = dispatch_record(11, ping_payload(b"once"));
    let key = record.message_key;

    let (mut sequencer, _mempool_handle) = start_sequencer(cross_zone_test_config()).await;
    sequencer
        .block_store()
        .storage_ref()
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![record],
        })
        .await
        .unwrap();

    let first = sequencer.run_production_turn().await.unwrap();
    let second = sequencer.run_production_turn().await.unwrap();

    let delivered_in = async |block_id: u64| {
        dispatches_in(
            &sequencer
                .store
                .block_at_id(block_id)
                .await
                .unwrap()
                .expect("produced block is stored"),
        )
    };
    assert_eq!(delivered_in(first).await, vec![key]);
    assert!(
        delivered_in(second).await.is_empty(),
        "the inbox seen-set must keep the drain from re-delivering"
    );

    let message = extract_cross_zone_dispatch(&dispatch_tx(11, ping_payload(b"once")))
        .expect("the dispatch carries a cross-zone message");
    assert!(
        sequencer
            .with_state(|state| dispatch_already_delivered(state, &message))
            .await,
        "the seen shard in head state is what the skip reads"
    );
}

#[tokio::test]
async fn a_dispatch_that_never_executes_is_given_up_on_after_repeated_failures() {
    // A payload that is not `u32`-aligned: the inbox guest rejects it outright,
    // so this is a delivery that can never execute however often it is retried.
    // Its content is chosen on the peer zone and validated by nobody in between,
    // so without a give-up policy it would fail on every block for ever.
    let record = dispatch_record(13, b"odd".to_vec());

    let (mut sequencer, _mempool_handle) = start_sequencer(cross_zone_test_config()).await;
    sequencer
        .block_store()
        .storage_ref()
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![record],
        })
        .await
        .unwrap();

    for attempt in 1..RETIRE_DISPATCH_AFTER_FAILURES {
        let block_id = sequencer.run_production_turn().await.unwrap();
        let block = sequencer
            .store
            .block_at_id(block_id)
            .await
            .unwrap()
            .expect("produced block is stored");
        assert!(
            dispatches_in(&block).is_empty(),
            "a dispatch that fails to execute must not reach the block"
        );

        let records = pending_dispatches(&sequencer).await;
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].failed_attempts, attempt,
            "the counter advances once per block, not once per process start"
        );
    }

    // The attempt at the limit gives up on it, which takes the record out of the
    // pending list. Anything else leaves an entry no later block can ever
    // remove, which is how a peer that can make deliveries fail would grow this
    // list without bound.
    sequencer.run_production_turn().await.unwrap();
    assert!(
        pending_dispatches(&sequencer).await.is_empty(),
        "giving up on a delivery must take its record out of the pending list"
    );

    // The dead letter is the only record that this happened, and the origin is
    // what identifies which message stopped being attempted.
    let (dead_letter_count, dead_letters) = sequencer.cross_zone_dead_letters().await.unwrap();
    assert_eq!(dead_letters.len(), 1);
    assert_eq!(
        dead_letters[0].origin,
        DispatchOrigin {
            src_zone: PEER_ZONE,
            src_block_id: 13,
            src_tx_index: 0,
        }
    );
    assert_eq!(
        dead_letters[0].message_key,
        cross_zone_inbox_core::message_key(&PEER_ZONE, 13, 0)
    );
    assert!(!dead_letters[0].transaction.is_empty());
    assert_eq!(
        dead_letters[0].failed_attempts,
        RETIRE_DISPATCH_AFTER_FAILURES
    );
    assert_eq!(dead_letter_count, 1);

    // The same view the RPC serves, so an operator sees what the store holds.
    let (total_retired, retained) = sequencer.cross_zone_dead_letters().await.unwrap();
    assert_eq!(total_retired, 1);
    assert_eq!(retained, dead_letters);

    // And nothing re-feeds it, so it stops costing a guest execution per block.
    let block_id = sequencer.run_production_turn().await.unwrap();
    let block = sequencer
        .store
        .block_at_id(block_id)
        .await
        .unwrap()
        .unwrap();
    assert!(dispatches_in(&block).is_empty());
    assert!(pending_dispatches(&sequencer).await.is_empty());
}

#[tokio::test]
async fn a_redelivered_record_is_dropped_once_its_delivery_is_irreversible() {
    // The watcher persists its floor only at slot boundaries, so a crash inside
    // a slot makes the next run re-read it and re-record deliveries that have
    // already settled. Their keys are in the inbox seen-set for good, so no
    // future block will ever carry them and the settlement path cannot reach
    // them. The drain dropping them is the only thing that does.
    let record = dispatch_record(29, ping_payload(b"again"));
    let key = record.message_key;

    let (mut sequencer, mempool_handle) = start_sequencer(cross_zone_test_config()).await;
    sequencer
        .block_store()
        .storage_ref()
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![record.clone()],
        })
        .await
        .unwrap();

    let block_id = sequencer.run_production_turn().await.unwrap();
    let delivery_block = sequencer
        .store
        .block_at_id(block_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dispatches_in(&delivery_block), vec![key]);

    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            checkpoint: checkpoint_at(mock_msg_of(&delivery_block)),
            finalized: vec![delivery_block],
            ..empty_follow_update()
        },
    )
    .await;
    assert!(pending_dispatches(&sequencer).await.is_empty());

    // The watcher re-reads the slot and records it again.
    sequencer
        .block_store()
        .storage_ref()
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![record],
        })
        .await
        .unwrap();
    assert_eq!(pending_dispatches(&sequencer).await.len(), 1);

    let block_id = sequencer.run_production_turn().await.unwrap();
    let block = sequencer
        .store
        .block_at_id(block_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        dispatches_in(&block).is_empty(),
        "the delivery is already on the chain, so it must not be delivered again"
    );
    assert!(
        pending_dispatches(&sequencer).await.is_empty(),
        "a record whose delivery is already irreversible must be dropped, not kept for ever"
    );
}

#[tokio::test]
async fn a_delivery_still_reversible_keeps_its_record() {
    // The counterpart to the test above, and the reason the drain checks two
    // states rather than one. In head but not yet final means the delivery can
    // still orphan, so skipping it is right but dropping its record would lose
    // the delivery when it does.
    let record = dispatch_record(31, ping_payload(b"pending"));
    let key = record.message_key;

    let (mut sequencer, _mempool_handle) = start_sequencer(cross_zone_test_config()).await;
    sequencer
        .block_store()
        .storage_ref()
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![record],
        })
        .await
        .unwrap();

    sequencer.run_production_turn().await.unwrap();
    sequencer.run_production_turn().await.unwrap();

    assert_eq!(
        pending_dispatches(&sequencer)
            .await
            .iter()
            .map(|record| record.message_key)
            .collect::<Vec<_>>(),
        vec![key],
        "nothing has finalized, so the record must survive in case the block orphans"
    );
}

#[test]
fn a_settled_delivery_that_is_not_the_one_we_recorded_is_reported() {
    // The message key covers (src_zone, src_block_id, src_tx_index) and nothing
    // about the payload, and so does the inbox's own replay check. So a peer's
    // sequencer can publish a delivery under a key we hold with a payload we
    // never saw, and it settles our correct record along with it. The indexer
    // catches the forgery and halts; this record is the last local copy of what
    // we believed, so the mismatch has to be reported before it is dropped.
    let honest = dispatch_record(53, ping_payload(b"honest"));
    let key = honest.message_key;
    let forged = dispatch_tx(53, ping_payload(b"forged"));
    assert_eq!(
        extract_cross_zone_dispatch_key(&forged),
        Some(key),
        "the forged delivery must share the key, or it proves nothing"
    );

    let block = common::test_utils::produce_dummy_block(2, None, vec![forged]);
    let (keys, mismatched) = classify_settled_deliveries(std::slice::from_ref(&honest), &block);
    assert_eq!(keys, vec![key], "the record is settled either way");
    assert_eq!(
        mismatched,
        vec![key],
        "a delivery that differs from the one recorded under that key must be reported"
    );

    // The honest case must stay quiet, or the report is noise.
    let honest_block = common::test_utils::produce_dummy_block(
        2,
        None,
        vec![dispatch_tx(53, ping_payload(b"honest"))],
    );
    let (keys, mismatched) = classify_settled_deliveries(&[honest], &honest_block);
    assert_eq!(keys, vec![key]);
    assert!(mismatched.is_empty());
}

#[tokio::test]
async fn a_delivery_too_large_for_any_block_does_not_stall_production() {
    // A store-drained transaction is at the head of the queue every turn, so one
    // that cannot fit in any block would defer itself for ever and, because the
    // deferral breaks the loop, stop production ever reaching the mempool behind
    // it. The peer chooses the payload, so this is theirs to trigger.
    let record = dispatch_record(41, ping_payload(&[7_u8; 8192]));

    let mut config = cross_zone_test_config();
    config.max_block_size = bytesize::ByteSize::kib(4);
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;
    sequencer
        .block_store()
        .storage_ref()
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![record],
        })
        .await
        .unwrap();

    let user_tx = common::test_utils::create_transaction_native_token_transfer(
        initial_public_user_accounts()[0].account_id,
        0,
        initial_public_user_accounts()[1].account_id,
        10,
        &create_signing_key_for_account1(),
    );
    mempool_handle
        .push((TransactionOrigin::User, user_tx.clone()))
        .await
        .unwrap();

    // Production must get past it to the mempool in the very first block.
    let block_id = sequencer.run_production_turn().await.unwrap();
    let block = sequencer
        .store
        .block_at_id(block_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        block.body.transactions.contains(&user_tx),
        "an oversized drained delivery must not stop production reaching the mempool"
    );
    assert!(dispatches_in(&block).is_empty());

    // And it is given up on rather than retried for ever.
    for _ in 1..RETIRE_DISPATCH_AFTER_FAILURES {
        sequencer.run_production_turn().await.unwrap();
    }
    assert!(
        pending_dispatches(&sequencer).await.is_empty(),
        "a delivery that fits in no block must be given up on"
    );
}

#[tokio::test]
async fn a_delivery_backlog_is_spread_across_blocks() {
    // Each delivery costs a guest execution and peers decide how many queue up,
    // so an unbounded drain would let a backlog decide how long a block takes to
    // build and leave no room for user work, since store-drained transactions
    // are taken before the mempool.
    let backlog = MAX_DISPATCHES_PER_BLOCK + 3;
    let records: Vec<_> = (0..backlog)
        .map(|index| {
            let src_block_id = 100 + u64::try_from(index).expect("test index fits");
            dispatch_record(src_block_id, ping_payload(b"backlog"))
        })
        .collect();

    let mut config = cross_zone_test_config();
    config.max_num_tx_in_block = backlog + 10;
    let (mut sequencer, _mempool_handle) = start_sequencer(config).await;
    sequencer
        .block_store()
        .storage_ref()
        .ask(AddPendingCrossZoneDispatches {
            dispatches: records,
        })
        .await
        .unwrap();

    let block_id = sequencer.run_production_turn().await.unwrap();
    let block = sequencer
        .store
        .block_at_id(block_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        dispatches_in(&block).len(),
        MAX_DISPATCHES_PER_BLOCK,
        "one block must not carry an unbounded number of deliveries"
    );

    // Deferred, not dropped: the rest go in the next block.
    let block_id = sequencer.run_production_turn().await.unwrap();
    let block = sequencer
        .store
        .block_at_id(block_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dispatches_in(&block).len(), 3);
}

#[test]
fn transaction_pre_check_pass() {
    let tx = common::test_utils::produce_dummy_empty_transaction();
    let result = tx.transaction_stateless_check();

    assert!(result.is_ok());
}

#[tokio::test]
async fn transaction_pre_check_native_transfer_valid() {
    let (_sequencer, _mempool_handle) = common_setup().await;

    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;

    let sign_key1 = create_signing_key_for_account1();

    let tx =
        common::test_utils::create_transaction_native_token_transfer(acc1, 0, acc2, 10, &sign_key1);
    let result = tx.transaction_stateless_check();

    assert!(result.is_ok());
}

#[tokio::test]
async fn transaction_pre_check_native_transfer_other_signature() {
    let (sequencer, _mempool_handle) = common_setup().await;

    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;

    let sign_key2 = create_signing_key_for_account2();

    let tx =
        common::test_utils::create_transaction_native_token_transfer(acc1, 0, acc2, 10, &sign_key2);

    // Signature is valid, stateless check pass
    let tx = tx.transaction_stateless_check().unwrap();

    // Signature is not from sender. Execution fails
    let result = tx.execute_check_on_state(sequencer.chain().lock().await.head_state_mut(), 0, 0);

    assert!(matches!(
        result,
        Err(lee::error::LeeError::ProgramExecutionFailed(_))
    ));
}

#[tokio::test]
async fn transaction_pre_check_native_transfer_sent_too_much() {
    let (sequencer, _mempool_handle) = common_setup().await;

    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;

    let sign_key1 = create_signing_key_for_account1();

    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1, 0, acc2, 10_000_000, &sign_key1,
    );

    let result = tx.transaction_stateless_check();

    // Passed pre-check
    assert!(result.is_ok());

    let result = result.unwrap().execute_check_on_state(
        sequencer.chain().lock().await.head_state_mut(),
        0,
        0,
    );
    let is_failed_at_balance_mismatch = matches!(
        result.err().unwrap(),
        lee::error::LeeError::ProgramExecutionFailed(_)
    );

    assert!(is_failed_at_balance_mismatch);
}

#[tokio::test]
async fn transaction_execute_native_transfer() {
    let (sequencer, _mempool_handle) = common_setup().await;

    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;

    let sign_key1 = create_signing_key_for_account1();

    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1, 0, acc2, 100, &sign_key1,
    );

    tx.execute_check_on_state(sequencer.chain().lock().await.head_state_mut(), 0, 0)
        .unwrap();

    let bal_from = sequencer
        .with_state(|s| s.get_account_by_id(acc1).balance)
        .await;
    let bal_to = sequencer
        .with_state(|s| s.get_account_by_id(acc2).balance)
        .await;

    assert_eq!(bal_from, 9900);
    assert_eq!(bal_to, 20100);
}

#[tokio::test]
async fn push_tx_into_mempool_blocks_until_mempool_is_full() {
    let config = SequencerConfig {
        mempool_max_size: 1,
        ..setup_sequencer_config()
    };
    let (mut sequencer, mempool_handle) = common_setup_with_config(config).await;

    let tx = common::test_utils::produce_dummy_empty_transaction();

    // Fill the mempool
    mempool_handle
        .push((TransactionOrigin::User, tx.clone()))
        .await
        .unwrap();

    // Check that pushing another transaction will block
    let mut push_fut = pin!(mempool_handle.push((TransactionOrigin::User, tx.clone())));
    let poll = futures::poll!(push_fut.as_mut());
    assert!(poll.is_pending());

    // Empty the mempool by producing a block
    sequencer.run_production_turn().await.unwrap();

    // Resolve the pending push
    assert!(push_fut.await.is_ok());
}

#[tokio::test]
async fn build_block_from_mempool() {
    let (mut sequencer, mempool_handle) = common_setup().await;
    let genesis_height = sequencer.chain_height().await;

    let tx = common::test_utils::produce_dummy_empty_transaction();
    mempool_handle
        .push((TransactionOrigin::User, tx))
        .await
        .unwrap();

    let result = sequencer
        .build_block_from_mempool(Some(&empty_committee()))
        .await;
    assert!(result.is_ok());
    // Building itself does not advance the head; only apply-after-publish does.
    assert_eq!(sequencer.chain_height().await, genesis_height);
}

/// The live committee the mock publisher reports: no keys, at the config entry
/// [`mock::checkpoint_at`] calls finalized.
fn empty_committee() -> LiveCommittee {
    LiveCommittee::at(Vec::new(), MsgId::root())
}

#[tokio::test]
async fn a_stake_only_moves_the_committee_once_it_has_finalized() {
    // Genesis stakes the bootstrap key, so the head wants it accredited already.
    let (mut sequencer, mempool_handle) = common_setup().await;

    assert!(
        sequencer
            .build_block_from_mempool(Some(&empty_committee()))
            .await
            .unwrap()
            .committee_update
            .is_none(),
        "an unfinalized stake must not move the committee"
    );

    let genesis = sequencer
        .store
        .block_at_id(lee_core::GENESIS_BLOCK_ID)
        .await
        .unwrap()
        .unwrap();
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            finalized: vec![genesis],
            ..empty_follow_update()
        },
    )
    .await;

    let wanted = sequencer
        .build_block_from_mempool(Some(&empty_committee()))
        .await
        .unwrap()
        .committee_update
        .expect("the stake is irreversible now, so the committee should follow it");
    assert!(
        sequencer
            .build_block_from_mempool(Some(&LiveCommittee::at(wanted, MsgId::root())))
            .await
            .unwrap()
            .committee_update
            .is_none(),
        "a committee that already matches must not be resubmitted"
    );
}

#[test]
fn the_committee_gate_holds_back_neither_ordinary_txs_nor_unknown_accounts() {
    let state = V03State::new();
    let finalize_unstake = build_finalize_unstake_tx(
        AccountId::new([1; 32]),
        sequencer_stake_core::PendingUnstake {
            amount: 10,
            destination: AccountId::new([2; 32]),
        },
    )
    .expect("FinalizeUnstake tx should build");

    // An ownership account no state knows about is left to the program to reject.
    assert!(finalize_unstake_is_includable(
        &state,
        &finalize_unstake,
        None
    ));
    assert!(finalize_unstake_is_includable(
        &state,
        &common::test_utils::produce_dummy_empty_transaction(),
        None
    ));
}

#[tokio::test]
async fn replay_transactions_are_rejected_in_the_same_block() {
    let (mut sequencer, mempool_handle) = common_setup().await;

    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;

    let sign_key1 = create_signing_key_for_account1();

    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1, 0, acc2, 100, &sign_key1,
    );

    let tx_original = tx.clone();
    let tx_replay = tx.clone();
    // Pushing two copies of the same tx to the mempool
    mempool_handle
        .push((TransactionOrigin::User, tx_original))
        .await
        .unwrap();
    mempool_handle
        .push((TransactionOrigin::User, tx_replay))
        .await
        .unwrap();

    // Create block
    sequencer.run_production_turn().await.unwrap();
    let block = sequencer
        .store
        .block_at_id(sequencer.chain_height().await)
        .await
        .unwrap()
        .unwrap();

    // Only one user tx should be included; the clock tx is always appended last.
    assert_eq!(
        block.body.transactions,
        vec![
            tx.clone(),
            LeeTransaction::Public(clock_invocation(block.header.timestamp))
        ]
    );
}

#[tokio::test]
async fn replay_transactions_are_rejected_in_different_blocks() {
    let (mut sequencer, mempool_handle) = common_setup().await;

    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;

    let sign_key1 = create_signing_key_for_account1();

    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1, 0, acc2, 100, &sign_key1,
    );

    // The transaction should be included the first time
    mempool_handle
        .push((TransactionOrigin::User, tx.clone()))
        .await
        .unwrap();
    sequencer.run_production_turn().await.unwrap();
    let block = sequencer
        .store
        .block_at_id(sequencer.chain_height().await)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        block.body.transactions,
        vec![
            tx.clone(),
            LeeTransaction::Public(clock_invocation(block.header.timestamp))
        ]
    );

    // Add same transaction should fail
    mempool_handle
        .push((TransactionOrigin::User, tx.clone()))
        .await
        .unwrap();
    sequencer.run_production_turn().await.unwrap();
    let block = sequencer
        .store
        .block_at_id(sequencer.chain_height().await)
        .await
        .unwrap()
        .unwrap();
    // The replay is rejected, so only the clock tx is in the block.
    assert_eq!(
        block.body.transactions,
        vec![LeeTransaction::Public(clock_invocation(
            block.header.timestamp
        ))]
    );
}

#[tokio::test]
async fn restart_from_storage() {
    let config = setup_sequencer_config();
    let acc1_account_id = initial_public_user_accounts()[0].account_id;
    let acc2_account_id = initial_public_user_accounts()[1].account_id;
    let balance_to_move = 13;

    // In the following code block a transaction will be processed that moves `balance_to_move`
    // from `acc_1` to `acc_2`. The block created with that transaction will be kept stored in
    // the temporary directory for the block storage of this test.
    let storage_weak = {
        let (mut sequencer, mempool_handle) = start_sequencer(config.clone()).await;
        let signing_key = create_signing_key_for_account1();

        let tx = common::test_utils::create_transaction_native_token_transfer(
            acc1_account_id,
            0,
            acc2_account_id,
            balance_to_move,
            &signing_key,
        );

        mempool_handle
            .push((TransactionOrigin::User, tx.clone()))
            .await
            .unwrap();
        sequencer.run_production_turn().await.unwrap();
        let block = sequencer
            .store
            .block_at_id(sequencer.chain_height().await)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            block.body.transactions,
            vec![
                tx.clone(),
                LeeTransaction::Public(clock_invocation(block.header.timestamp))
            ]
        );
        sequencer.block_store().storage_ref().downgrade()
    };
    storage_weak.wait_for_shutdown_with_result(|_| ()).await;

    // Instantiating a new sequencer from the same config. This should load the existing block
    // with the above transaction and update the state to reflect that.
    let (sequencer, _mempool_handle) = start_sequencer(config.clone()).await;
    let balance_acc_1 = sequencer
        .with_state(|s| s.get_account_by_id(acc1_account_id).balance)
        .await;
    let balance_acc_2 = sequencer
        .with_state(|s| s.get_account_by_id(acc2_account_id).balance)
        .await;

    // Balances should be consistent with the stored block
    assert_eq!(
        balance_acc_1,
        initial_public_user_accounts()[0].balance - balance_to_move
    );
    assert_eq!(
        balance_acc_2,
        initial_public_user_accounts()[1].balance + balance_to_move
    );
}

#[tokio::test]
async fn get_pending_blocks() {
    let config = setup_sequencer_config();
    let (mut sequencer, _mempool_handle) = start_sequencer(config).await;
    sequencer.run_production_turn().await.unwrap();
    sequencer.run_production_turn().await.unwrap();
    sequencer.run_production_turn().await.unwrap();
    assert_eq!(sequencer.get_pending_blocks().await.unwrap().len(), 4);
}

#[tokio::test]
async fn delete_blocks() {
    let config = setup_sequencer_config();
    let (mut sequencer, _mempool_handle) = start_sequencer(config).await;
    sequencer.run_production_turn().await.unwrap();
    sequencer.run_production_turn().await.unwrap();
    sequencer.run_production_turn().await.unwrap();

    let last_finalized_block = 3;
    sequencer
        .clean_finalized_blocks_from_db(last_finalized_block)
        .await
        .unwrap();

    assert_eq!(sequencer.get_pending_blocks().await.unwrap().len(), 1);
}

#[tokio::test]
async fn produce_block_with_correct_prev_meta_after_restart() {
    let config = setup_sequencer_config();
    let acc1_account_id = initial_public_user_accounts()[0].account_id;
    let acc2_account_id = initial_public_user_accounts()[1].account_id;

    // Step 1: Create initial database with some block metadata
    let (storage_weak, expected_prev_meta) = {
        let (mut sequencer, mempool_handle) = start_sequencer(config.clone()).await;

        let signing_key = create_signing_key_for_account1();

        // Add a transaction and produce a block to set up block metadata
        let tx = common::test_utils::create_transaction_native_token_transfer(
            acc1_account_id,
            0,
            acc2_account_id,
            100,
            &signing_key,
        );

        mempool_handle
            .push((TransactionOrigin::User, tx))
            .await
            .unwrap();
        sequencer.run_production_turn().await.unwrap();

        // Get the metadata of the last block produced
        let meta = sequencer.store.latest_block_meta().await.unwrap().unwrap();
        (sequencer.block_store().storage_ref().downgrade(), meta)
    };
    storage_weak.wait_for_shutdown_with_result(|_| ()).await;

    // Step 2: Restart sequencer from the same storage
    let (mut sequencer, mempool_handle) = start_sequencer(config.clone()).await;

    // Step 3: Submit a new transaction
    let signing_key = create_signing_key_for_account1();
    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1_account_id,
        1, // Next nonce
        acc2_account_id,
        50,
        &signing_key,
    );

    mempool_handle
        .push((TransactionOrigin::User, tx.clone()))
        .await
        .unwrap();

    // Step 4: Produce new block
    sequencer.run_production_turn().await.unwrap();

    // Step 5: Verify the new block has correct previous block metadata
    let new_block = sequencer
        .store
        .block_at_id(sequencer.chain_height().await)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        new_block.header.prev_block_hash, expected_prev_meta.hash,
        "New block's prev_block_hash should match the stored metadata hash"
    );
    assert_eq!(
        new_block.body.transactions,
        vec![
            tx,
            LeeTransaction::Public(clock_invocation(new_block.header.timestamp))
        ],
        "New block should contain the submitted transaction and the clock invocation"
    );
}

#[tokio::test]
async fn transactions_touching_clock_account_are_dropped_from_block() {
    let (mut sequencer, mempool_handle) = common_setup().await;

    // Canonical clock invocation and a crafted variant with a different timestamp — both must
    // be dropped because their diffs touch the clock accounts.
    let crafted_clock_tx = {
        let message = lee::public_transaction::Message::try_new(
            programs::clock().id(),
            system_accounts::clock_account_ids().to_vec(),
            vec![],
            42_u64,
        )
        .unwrap();
        LeeTransaction::Public(lee::PublicTransaction::new(
            message,
            lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
        ))
    };
    mempool_handle
        .push((
            TransactionOrigin::User,
            LeeTransaction::Public(clock_invocation(0)),
        ))
        .await
        .unwrap();
    mempool_handle
        .push((TransactionOrigin::User, crafted_clock_tx))
        .await
        .unwrap();
    sequencer.run_production_turn().await.unwrap();

    let block = sequencer
        .store
        .block_at_id(sequencer.chain_height().await)
        .await
        .unwrap()
        .unwrap();

    // Both transactions were dropped. Only the system-appended clock tx remains.
    assert_eq!(
        block.body.transactions,
        vec![LeeTransaction::Public(clock_invocation(
            block.header.timestamp
        ))]
    );
}

#[tokio::test]
async fn user_tx_that_chain_calls_clock_is_dropped() {
    let (mut sequencer, mempool_handle) = common_setup().await;

    let clock_chain_caller = test_programs::clock_chain_caller();
    // Deploy the clock_chain_caller test program.
    let deploy_tx = LeeTransaction::ProgramDeployment(lee::ProgramDeploymentTransaction::new(
        lee::program_deployment_transaction::Message::new(clock_chain_caller.elf().to_owned()),
    ));
    mempool_handle
        .push((TransactionOrigin::User, deploy_tx))
        .await
        .unwrap();
    sequencer.run_production_turn().await.unwrap();

    // Build a user transaction that invokes clock_chain_caller, which in turn chain-calls the
    // clock program with the clock accounts. The sequencer should detect that the resulting
    // state diff modifies clock accounts and drop the transaction.
    let clock_chain_caller_id = test_programs::clock_chain_caller().id();
    let clock_program_id = programs::clock().id();
    let timestamp: u64 = 0;

    let message = lee::public_transaction::Message::try_new(
        clock_chain_caller_id,
        system_accounts::clock_account_ids().to_vec(),
        vec![], // no signers
        (clock_program_id, timestamp),
    )
    .unwrap();
    let user_tx = LeeTransaction::Public(lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    ));

    mempool_handle
        .push((TransactionOrigin::User, user_tx))
        .await
        .unwrap();
    sequencer.run_production_turn().await.unwrap();

    let block = sequencer
        .store
        .block_at_id(sequencer.chain_height().await)
        .await
        .unwrap()
        .unwrap();

    // The user tx must have been dropped; only the mandatory clock invocation remains.
    assert_eq!(
        block.body.transactions,
        vec![LeeTransaction::Public(clock_invocation(
            block.header.timestamp
        ))]
    );
}

#[tokio::test]
async fn block_production_aborts_when_clock_account_data_is_corrupted() {
    let (mut sequencer, mempool_handle) = common_setup().await;

    // Corrupt the clock 01 account data so the clock program panics on deserialization.
    let clock_account_id = system_accounts::clock_account_ids()[0];
    let mut corrupted = sequencer
        .with_state(|s| s.get_account_by_id(clock_account_id))
        .await;
    corrupted.data = vec![0xff; 3].try_into().unwrap();
    sequencer
        .chain()
        .lock()
        .await
        .head_state_mut()
        .force_insert_account(clock_account_id, corrupted);

    // Push a dummy transaction so the mempool is non-empty.
    let tx = common::test_utils::produce_dummy_empty_transaction();
    mempool_handle
        .push((TransactionOrigin::User, tx))
        .await
        .unwrap();

    // Block production must fail because the appended clock tx cannot execute.
    let result = sequencer.run_production_turn().await;
    assert!(
        result.is_err(),
        "Block production should abort when clock account data is corrupted"
    );
}

// #[test]
// fn private_bridge_withdraw_invocation_is_dropped() {
//     let sender_keys = KeyChain::new_os_random();
//     let sender_account_id = AccountId::for_regular_private_account(
//         &sender_keys.nullifier_public_key,
//         &sender_keys.viewing_public_key,
//         0,
//     );
//     let sender_private_account = Account {
//         program_owner: programs::authenticated_transfer().id().into(),
//         balance: 100,
//         nonce: Nonce(0xdead_beef),
//         data: Data::default(),
//     };
//     let bridge_account_id = system_accounts::bridge_account_id();

//     let mut state = V03State::new()
//         .with_public_accounts([(bridge_account_id, system_accounts::bridge_account())])
//         .with_private_accounts([(
//             Commitment::new(&sender_account_id, &sender_private_account),
//             Nullifier::for_account_initialization(&sender_account_id),
//         )]);

//     let sender_commitment = Commitment::new(&sender_account_id, &sender_private_account);

//     let sender_pre = AccountWithMetadata::new(
//         sender_private_account,
//         true,
//         (
//             &sender_keys.nullifier_public_key,
//             &sender_keys.viewing_public_key,
//             0,
//         ),
//     );
//     let bridge_pre = AccountWithMetadata::new(
//         state.get_account_by_id(bridge_account_id),
//         false,
//         bridge_account_id,
//     );

//     let instruction = Program::serialize_instruction(bridge_core::Instruction::Withdraw {
//         amount: 1,
//         bedrock_account_pk: [0; 32],
//     })
//     .unwrap();

//     let program_with_deps = ProgramWithDependencies::new(
//         programs::bridge(),
//         [(
//             programs::authenticated_transfer().id(),
//             programs::authenticated_transfer(),
//         )]
//         .into(),
//     );

//     let (output, proof) = execute_and_prove(
//         vec![sender_pre, bridge_pre],
//         instruction,
//         vec![
//             InputAccountIdentity::PrivateAuthorizedUpdate {
//                 vpk: sender_keys.viewing_public_key.clone(),
//                 random_seed: [0; 32],
//                 view_tag: 0,
//                 nsk: sender_keys.private_key_holder.nullifier_secret_key,
//                 membership_proof: state
//                     .get_proof_for_commitment(&sender_commitment)
//                     .expect("sender commitment must be in state"),
//                 identifier: 0,
//             },
//             InputAccountIdentity::Public,
//         ],
//         &program_with_deps,
//     )
//     .expect("Execution should succeed");

//     let message = Message::try_from_circuit_output(vec![bridge_account_id], vec![], output)
//         .expect("Message construction should succeed");
//     let witness_set =
//         lee::privacy_preserving_transaction::WitnessSet::for_message(&message, proof, &[]);
//     let tx =
//         LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(message,
// witness_set));     let res = tx.execute_check_on_state(&mut state, 1, 0);

//     assert!(
//         matches!(res, Err(LeeError::InvalidInput(_))),
//         "Bridge withdraw invocation should be rejected in private execution"
//     );
// }

/// Builds a [`V03State`] with the clock program and `program` registered, the three clock
/// accounts initialized, and the clock advanced to `clock_timestamp` so that reads of the
/// `CLOCK_01` account observe it.
fn state_with_clock_and_program(program: Program, clock_timestamp: u64) -> V03State {
    let mut state = V03State::new().with_programs([programs::clock(), program]);
    for clock_id in system_accounts::clock_account_ids() {
        state.force_insert_account(clock_id, system_accounts::clock_account());
    }
    state
        .transition_from_public_transaction(&clock_invocation(clock_timestamp), 1, clock_timestamp)
        .expect("Clock invocation should advance the clock");
    state
}

fn time_locked_transfer_transaction(
    from: AccountId,
    from_key: &PrivateKey,
    from_nonce: u128,
    to: AccountId,
    clock_account_id: AccountId,
    amount: u128,
    deadline: u64,
) -> PublicTransaction {
    let program_id = test_programs::time_locked_transfer().id();
    let message = lee::public_transaction::Message::try_new(
        program_id,
        vec![from, to, clock_account_id],
        vec![Nonce(from_nonce)],
        (amount, deadline),
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[from_key]);
    PublicTransaction::new(message, witness_set)
}

#[test]
fn time_locked_transfer_succeeds_when_deadline_has_passed() {
    let clock_timestamp = 600;
    let mut state =
        state_with_clock_and_program(test_programs::time_locked_transfer(), clock_timestamp);

    // The recipient must be a non-default account so the program may credit it without
    // claiming it.
    let recipient_id = AccountId::new([42; 32]);
    state.force_insert_account(
        recipient_id,
        Account {
            program_owner: programs::authenticated_transfer().id().into(),
            ..Account::default()
        },
    );

    let key1 = PrivateKey::try_new([1; 32]).unwrap();
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&key1));
    state.force_insert_account(
        sender_id,
        Account {
            program_owner: test_programs::time_locked_transfer().id().into(),
            balance: 100,
            ..Account::default()
        },
    );

    let amount = 100;
    // Deadline is in the past relative to the clock, so the transfer is unlocked.
    let deadline = 0;

    let tx = time_locked_transfer_transaction(
        sender_id,
        &key1,
        0,
        recipient_id,
        system_accounts::clock_account_ids()[0],
        amount,
        deadline,
    );

    state
        .transition_from_public_transaction(&tx, 2, clock_timestamp)
        .unwrap();

    // Balances changed.
    assert_eq!(state.get_account_by_id(sender_id).balance, 0);
    assert_eq!(state.get_account_by_id(recipient_id).balance, 100);
}

#[test]
fn time_locked_transfer_fails_when_deadline_is_in_the_future() {
    let clock_timestamp = 600;
    let mut state =
        state_with_clock_and_program(test_programs::time_locked_transfer(), clock_timestamp);

    let recipient_id = AccountId::new([42; 32]);
    state.force_insert_account(
        recipient_id,
        Account {
            program_owner: programs::authenticated_transfer().id().into(),
            ..Account::default()
        },
    );

    let key1 = PrivateKey::try_new([1; 32]).unwrap();
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&key1));
    state.force_insert_account(
        sender_id,
        Account {
            program_owner: test_programs::time_locked_transfer().id().into(),
            balance: 100,
            ..Account::default()
        },
    );

    let amount = 100;
    // Far-future deadline: the program panics because the clock has not reached it.
    let deadline = u64::MAX;

    let tx = time_locked_transfer_transaction(
        sender_id,
        &key1,
        0,
        recipient_id,
        system_accounts::clock_account_ids()[0],
        amount,
        deadline,
    );

    let result = state.transition_from_public_transaction(&tx, 2, clock_timestamp);

    assert!(
        result.is_err(),
        "Transfer should fail when deadline is in the future"
    );
    // Balances unchanged.
    assert_eq!(state.get_account_by_id(sender_id).balance, 100);
    assert_eq!(state.get_account_by_id(recipient_id).balance, 0);
}

fn cooldown_data(cooldown_ms: u64, last_run_timestamp: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(&cooldown_ms.to_le_bytes());
    buf.extend_from_slice(&last_run_timestamp.to_le_bytes());
    buf
}

fn cooldown_transaction(state_id: AccountId, clock_account_id: AccountId) -> PublicTransaction {
    let program_id = test_programs::cooldown().id();
    let message = lee::public_transaction::Message::try_new(
        program_id,
        vec![state_id, clock_account_id],
        vec![],
        (),
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[]);
    PublicTransaction::new(message, witness_set)
}

#[test]
fn cooldown_opens_after_the_cooldown_elapses() {
    let state_id = AccountId::new([99; 32]);

    let genesis_timestamp = 1000;
    let cooldown_ms = 500;
    // Last run was at genesis, so any timestamp >= genesis + cooldown should work.
    let last_run_timestamp = genesis_timestamp;

    // Advance the clock so the cooldown check reads an updated timestamp.
    let block_timestamp = genesis_timestamp + cooldown_ms;
    let mut state = state_with_clock_and_program(test_programs::cooldown(), block_timestamp);

    state.force_insert_account(
        state_id,
        Account {
            program_owner: test_programs::cooldown().id().into(),
            data: cooldown_data(cooldown_ms, last_run_timestamp)
                .try_into()
                .unwrap(),
            ..Account::default()
        },
    );

    let tx = cooldown_transaction(state_id, system_accounts::clock_account_ids()[0]);

    state
        .transition_from_public_transaction(&tx, 2, block_timestamp)
        .unwrap();

    assert_eq!(
        state.get_account_by_id(state_id).data.as_ref(),
        cooldown_data(cooldown_ms, block_timestamp)
    );
}

#[test]
fn cooldown_rejects_before_the_cooldown_elapses() {
    let state_id = AccountId::new([99; 32]);

    let genesis_timestamp = 1000;
    let cooldown_ms = 500;
    let last_run_timestamp = genesis_timestamp;

    // Timestamp is only 100ms after the last run, well within the 500ms cooldown.
    let block_timestamp = genesis_timestamp + 100;
    let mut state = state_with_clock_and_program(test_programs::cooldown(), block_timestamp);

    state.force_insert_account(
        state_id,
        Account {
            program_owner: test_programs::cooldown().id().into(),
            data: cooldown_data(cooldown_ms, last_run_timestamp)
                .try_into()
                .unwrap(),
            ..Account::default()
        },
    );

    let tx = cooldown_transaction(state_id, system_accounts::clock_account_ids()[0]);

    let result = state.transition_from_public_transaction(&tx, 2, block_timestamp);

    assert!(
        result.is_err(),
        "The program should fail during the cooldown period"
    );
    assert_eq!(
        state.get_account_by_id(state_id).data.as_ref(),
        cooldown_data(cooldown_ms, last_run_timestamp)
    );
}

#[test]
fn resubmittable_txs_drops_clock_and_bridge_deposits() {
    let user_tx = common::test_utils::produce_dummy_empty_transaction();
    let deposit_tx = build_bridge_deposit_tx_from_event(&PendingDepositEventRecord {
        deposit_op_id: HashType([13; 32]),
        source_tx_hash: HashType([7; 32]),
        amount: 1,
        metadata: borsh::to_vec(&DepositMetadataForEncoding {
            recipient_id: initial_public_user_accounts()[0].account_id,
        })
        .unwrap(),
    })
    .unwrap();
    let withdraw_tx = {
        let message = lee::public_transaction::Message::try_new(
            programs::bridge().id(),
            vec![system_accounts::bridge_account_id()],
            vec![],
            bridge_core::Instruction::Withdraw {
                amount: 1,
                bedrock_account_pk: [0; 32],
            },
        )
        .unwrap();
        LeeTransaction::Public(PublicTransaction::new(
            message,
            lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
        ))
    };

    let block = common::test_utils::produce_dummy_block(
        2,
        Some(HashType([1; 32])),
        vec![user_tx.clone(), deposit_tx, withdraw_tx.clone()],
    );

    // The trailing clock tx and the sequencer-generated deposit are dropped;
    // user txs (withdrawals included) are returned.
    assert_eq!(resubmittable_txs(&block), vec![user_tx, withdraw_tx]);
}

#[test]
fn resubmittable_txs_of_blocks_without_user_txs_is_empty() {
    // No transactions at all (not even the mandatory clock tx).
    let empty = HashableBlockData {
        block_id: 1,
        prev_block_hash: HashType([0; 32]),
        timestamp: 0,
        transactions: vec![],
    }
    .into_pending_block(&sequencer_sign_key_for_testing());
    assert!(resubmittable_txs(&empty).is_empty());

    let clock_only = common::test_utils::produce_dummy_block(1, None, vec![]);
    assert!(resubmittable_txs(&clock_only).is_empty());
}

#[tokio::test]
async fn follow_update_persists_the_checkpoint_with_its_effects() {
    let config = setup_sequencer_config();
    let (sequencer, mempool_handle) = start_sequencer(config).await;
    let genesis_meta = sequencer
        .store
        .latest_block_meta()
        .await
        .unwrap()
        .expect("genesis meta is set");

    let peer_block = common::test_utils::produce_dummy_block(2, Some(genesis_meta.hash), vec![]);
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            adopted: vec![peer_block],
            ..empty_follow_update()
        },
    )
    .await;

    // The checkpoint is the sdk resume cursor; landing it without the block
    // would let a restart stream past a block the store never got.
    assert!(
        sequencer
            .store
            .get_zone_checkpoint()
            .await
            .unwrap()
            .is_some(),
        "the event's checkpoint must be persisted alongside the block it covers"
    );
    assert!(sequencer.store.block_at_id(2).await.unwrap().is_some());
}

/// A publish that never reaches the channel must leave its height free, or the
/// mark outlives the block and the node skips every later turn.
#[tokio::test]
async fn a_failed_publish_leaves_its_height_free() {
    let config = setup_sequencer_config();
    let (mut sequencer, _mempool_handle) = start_sequencer(config).await;

    let first = sequencer.run_production_turn().await.unwrap();
    let mark = sequencer.store.published_high_water().await.unwrap();
    assert_eq!(mark, Some(first));

    sequencer.block_publisher().fail_publishes();
    let failed = sequencer.run_production_turn().await;
    assert!(failed.is_err(), "the canned publish failure must surface");
    assert_eq!(
        sequencer.store.published_high_water().await.unwrap(),
        mark,
        "a block that never reached the channel must not claim its height"
    );
    assert!(
        sequencer.rewound_below_published().await.is_none(),
        "the next turn must still be allowed to run"
    );
}

/// A head rewound after the turn gate has already passed must not republish a
/// height the channel already carries.
#[tokio::test]
async fn a_rewind_after_the_turn_gate_does_not_republish_a_taken_height() {
    let config = setup_sequencer_config();
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    sequencer.run_production_turn().await.unwrap();
    let published_tip = sequencer.run_production_turn().await.unwrap();
    assert_eq!(
        sequencer.store.published_high_water().await.unwrap(),
        Some(published_tip)
    );

    // The tip is orphaned but stays inscribed, so the mark must hold.
    let tip_block = sequencer
        .store
        .block_at_id(published_tip)
        .await
        .unwrap()
        .unwrap();
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            checkpoint: checkpoint_at(MsgId::from([8_u8; 32])),
            orphaned: vec![tip_block.clone()],
            adopted: vec![tip_block],
            ..empty_follow_update()
        },
    )
    .await;

    // Rewind the head without touching the mark, as a reorg landing mid-turn
    // would.
    let readopted = sequencer
        .store
        .block_at_id(published_tip)
        .await
        .unwrap()
        .unwrap();
    sequencer.chain().lock().await.revert_orphan(&readopted);
    assert_eq!(sequencer.next_block_height().await, published_tip);
    assert_eq!(
        sequencer.store.published_high_water().await.unwrap(),
        Some(published_tip),
        "the mark still covers the height the turn is about to reuse"
    );

    let republished = sequencer.run_production_turn().await;
    assert!(
        republished.is_err(),
        "a turn must not inscribe a height the mark already covers"
    );
    assert_eq!(
        sequencer.store.published_high_water().await.unwrap(),
        Some(published_tip),
        "the refused turn leaves the mark untouched"
    );
}

/// A block is chained on the entry its head sat on, so a tip that moved between
/// building and publishing refuses the inscription instead of taking a height
/// the channel already carries.
#[tokio::test]
async fn a_block_is_refused_when_the_channel_tip_moved_under_it() {
    let config = setup_sequencer_config();
    let (mut sequencer, _mempool_handle) = start_sequencer(config).await;

    let first = sequencer.run_production_turn().await.unwrap();
    let mark = sequencer.store.published_high_water().await.unwrap();
    assert_eq!(mark, Some(first));

    // Someone else's inscription took the tip since our head was built.
    sequencer
        .block_publisher()
        .set_channel_tip(Some(MsgId::from([42_u8; 32])));

    let refused = sequencer.run_production_turn().await;
    assert!(
        refused.is_err(),
        "a block chained on a stale entry must not be inscribed"
    );
    assert_eq!(
        sequencer.store.published_high_water().await.unwrap(),
        mark,
        "the refused block leaves its height free"
    );
}

/// A skippable inscription (garbage, a config op) owns the channel tip without
/// moving the head. The cursor follows it, so the next block still lands —
/// pinned on the junk entry, its content chained on the last valid block.
#[tokio::test]
async fn production_chains_on_an_ignorable_inscription_at_the_tip() {
    let config = setup_sequencer_config();
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    let first = sequencer.run_production_turn().await.unwrap();

    // A peer's garbage inscription takes the tip; the sdk reports it only as
    // the checkpoint's tip, with an empty delta.
    let junk = MsgId::from([42_u8; 32]);
    sequencer.block_publisher().set_channel_tip(Some(junk));
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            checkpoint: checkpoint_at(junk),
            ..empty_follow_update()
        },
    )
    .await;

    let next = sequencer
        .run_production_turn()
        .await
        .expect("the pin must follow the channel tip past an ignorable inscription");
    assert_eq!(next, first + 1, "the junk owns no height");
}

/// A reorg that drops the entry the pin names must fall back to the entry the
/// reorg left behind, or every later publish is refused on a dead parent.
#[tokio::test]
async fn an_orphan_of_the_pinned_block_rewinds_to_the_surviving_entry() {
    let config = setup_sequencer_config();
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    sequencer.run_production_turn().await.unwrap();
    sequencer.run_production_turn().await.unwrap();
    let block2 = sequencer.store.block_at_id(2).await.unwrap().unwrap();
    let block3 = sequencer.store.block_at_id(3).await.unwrap().unwrap();
    let block2_msg = mock_msg_of(&block2);
    let block3_msg = mock_msg_of(&block3);
    assert_eq!(
        sequencer.chain().lock().await.pin_parent(),
        Some(block3_msg),
        "our newest publish owns the tip"
    );

    // The reorg drops our newest inscription; the one below it still stands,
    // and the checkpoint names it.
    sequencer
        .block_publisher()
        .set_channel_tip(Some(block2_msg));
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            checkpoint: checkpoint_at(block2_msg),
            orphaned: vec![block3],
            ..empty_follow_update()
        },
    )
    .await;

    assert_eq!(
        sequencer.chain().lock().await.pin_parent(),
        Some(block2_msg),
        "the pin must rewind onto the entry still on the branch"
    );
    sequencer
        .run_production_turn()
        .await
        .expect("the next block must pin on the entry the reorg left at the tip");
}

/// An orphaned entry that is not a block never reaches `orphaned` — nothing in
/// the head reverts for it — so only the checkpoint can rewind the pin off it.
#[tokio::test]
async fn an_orphan_of_an_ignorable_entry_rewinds_the_pin() {
    let config = setup_sequencer_config();
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    sequencer.run_production_turn().await.unwrap();
    let block2 = sequencer.store.block_at_id(2).await.unwrap().unwrap();
    let block2_msg = mock_msg_of(&block2);

    // A peer's garbage inscription takes the tip without moving the head.
    let junk = MsgId::from([42_u8; 32]);
    sequencer.block_publisher().set_channel_tip(Some(junk));
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            checkpoint: checkpoint_at(junk),
            ..empty_follow_update()
        },
    )
    .await;
    assert_eq!(sequencer.chain().lock().await.pin_parent(), Some(junk));

    // The reorg drops only the garbage, so the head sees nothing at all.
    sequencer
        .block_publisher()
        .set_channel_tip(Some(block2_msg));
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            checkpoint: checkpoint_at(block2_msg),
            ..empty_follow_update()
        },
    )
    .await;

    assert_eq!(
        sequencer.chain().lock().await.pin_parent(),
        Some(block2_msg),
        "the pin must come off an entry no report could revert"
    );
    sequencer
        .run_production_turn()
        .await
        .expect("the next block must pin on the block the garbage sat on");
}

/// Two ignorable entries stacked on the channel: dropping the newer one must
/// land the pin on the older, which neither tier can name — the checkpoint
/// alone holds it.
#[tokio::test]
async fn an_orphan_of_the_newest_ignorable_entry_falls_back_to_the_one_below() {
    let config = setup_sequencer_config();
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    sequencer.run_production_turn().await.unwrap();
    let first_junk = MsgId::from([41_u8; 32]);
    let second_junk = MsgId::from([42_u8; 32]);
    sequencer
        .block_publisher()
        .set_channel_tip(Some(second_junk));
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            checkpoint: checkpoint_at(second_junk),
            ..empty_follow_update()
        },
    )
    .await;
    assert_eq!(
        sequencer.chain().lock().await.pin_parent(),
        Some(second_junk)
    );

    // The reorg drops only the newer garbage.
    sequencer
        .block_publisher()
        .set_channel_tip(Some(first_junk));
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            checkpoint: checkpoint_at(first_junk),
            ..empty_follow_update()
        },
    )
    .await;

    assert_eq!(
        sequencer.chain().lock().await.pin_parent(),
        Some(first_junk),
        "the pin must land on the ignorable entry the reorg left at the tip"
    );
    sequencer
        .run_production_turn()
        .await
        .expect("the next block must pin on the surviving ignorable entry");
}

/// A fully finalized channel still pins: a pin of `None` is not "unpinned is
/// fine", it selects the racy publish. And the LIB-pruning orphan report that
/// follows finalization must not move the pin off an entry the channel holds.
#[tokio::test]
async fn the_pin_stays_on_a_finalized_entry_through_its_pruning_report() {
    let config = setup_sequencer_config();
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    sequencer.run_production_turn().await.unwrap();
    let block2 = sequencer.store.block_at_id(2).await.unwrap().unwrap();
    let block2_msg = mock_msg_of(&block2);

    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            checkpoint: checkpoint_at(block2_msg),
            finalized: vec![block2.clone()],
            ..empty_follow_update()
        },
    )
    .await;
    assert_eq!(
        sequencer.chain().lock().await.pin_parent(),
        Some(block2_msg),
        "the finalized entry carries the pin"
    );

    // LIB pruning reports our finalized inscription as orphaned a poll or two
    // later; the channel still holds it, so the checkpoint's tip stays put.
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            checkpoint: checkpoint_at(block2_msg),
            orphaned: vec![block2],
            ..empty_follow_update()
        },
    )
    .await;

    assert_eq!(
        sequencer.chain().lock().await.pin_parent(),
        Some(block2_msg),
        "an entry the channel still holds keeps the pin"
    );
    sequencer
        .run_production_turn()
        .await
        .expect("the next block must pin on the finalized tip");
}

/// A pin on an entry we published ourselves at startup must still produce,
/// even while the channel read is too old to show it.
#[tokio::test]
async fn the_pin_the_bootstrap_publishes_leave_survives_a_lagging_channel_read() {
    let mut config = setup_sequencer_config();
    // No channel yet, so startup creates it and publishes our stored blocks.
    config.bedrock_config.channel_id = ChannelId::from(crate::mock::ABSENT_CHANNEL_ID);
    let (mut sequencer, _mempool_handle) = start_sequencer(config).await;

    let pin = sequencer.chain().lock().await.pin_parent();
    assert!(pin.is_some(), "the bootstrap publishes leave a pin");

    // The read does not show our genesis yet.
    sequencer
        .block_publisher()
        .set_stale_tip_read(MsgId::from([42_u8; 32]));

    assert!(
        sequencer.pin_behind_channel_tip().await.is_none(),
        "a pin on our own bootstrap inscription must not be read as behind"
    );
    sequencer
        .run_production_turn()
        .await
        .expect("the first turn must produce, pinned on what the bootstrap published");
}

/// The sdk can deliver a checkpoint it built before our publishes, whose tip is
/// root on a channel that did not exist yet. Believing it would rewind the pin
/// onto a channel we have since filled.
#[tokio::test]
async fn a_buffered_startup_checkpoint_cannot_rewind_the_pin() {
    let mut config = setup_sequencer_config();
    config.bedrock_config.channel_id = ChannelId::from(crate::mock::ABSENT_CHANNEL_ID);
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    let pin = sequencer.chain().lock().await.pin_parent();
    assert!(pin.is_some(), "the bootstrap publishes leave a pin");

    // Built before our publishes, so it names none of them and its tip is root.
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            checkpoint: checkpoint_at(MsgId::root()),
            ..empty_follow_update()
        },
    )
    .await;

    assert_eq!(
        sequencer.chain().lock().await.pin_parent(),
        pin,
        "a stale startup tip must not rewind the pin off what the bootstrap published"
    );
    sequencer
        .run_production_turn()
        .await
        .expect("the turn after a stale startup checkpoint must still produce");
}

/// zone-sdk does not resubmit an orphan, so an orphan report that re-adopts
/// nothing frees the height for the next turn. A re-adopted block keeps it.
#[tokio::test]
async fn a_dropped_orphan_frees_the_published_height() {
    let config = setup_sequencer_config();
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    let first = sequencer.run_production_turn().await.unwrap();
    let published_tip = sequencer.run_production_turn().await.unwrap();
    assert_eq!(
        sequencer.store.published_high_water().await.unwrap(),
        Some(published_tip),
        "publishing records the high water mark"
    );

    let mut produced: Vec<Block> = Vec::new();
    for id in [first, published_tip] {
        produced.push(sequencer.store.block_at_id(id).await.unwrap().unwrap());
    }

    // The sdk orphans the tip and re-adopts it under a fresh inscription.
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            orphaned: vec![produced[1].clone()],
            adopted: vec![produced[1].clone()],
            ..empty_follow_update()
        },
    )
    .await;
    assert_eq!(
        sequencer.store.published_high_water().await.unwrap(),
        Some(published_tip),
        "a re-adopted block keeps the mark"
    );
    assert!(sequencer.rewound_below_published().await.is_none());

    // The sdk orphans both and re-adopts neither.
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            orphaned: produced.iter().map(Clone::clone).collect(),
            ..empty_follow_update()
        },
    )
    .await;
    // Dropping them takes the channel tip back with them.
    sequencer.block_publisher().set_channel_tip(None);

    assert_eq!(sequencer.next_block_height().await, first);
    assert_eq!(
        sequencer.store.published_high_water().await.unwrap(),
        Some(first - 1),
        "the mark follows the rewound head"
    );
    assert!(
        sequencer.rewound_below_published().await.is_none(),
        "the freed height is ours to produce again"
    );
    assert_eq!(
        sequencer.run_production_turn().await.unwrap(),
        first,
        "production resumes at the freed height"
    );
}

/// A block the channel put back is still on the channel, so its height stays
/// reserved even when another orphan in the same update was dropped.
#[tokio::test]
async fn a_readopted_block_above_the_head_keeps_the_published_height() {
    let config = setup_sequencer_config();
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    let first = sequencer.run_production_turn().await.unwrap();
    let second = sequencer.run_production_turn().await.unwrap();
    let third = sequencer.run_production_turn().await.unwrap();
    let mut produced: Vec<Block> = Vec::new();
    for id in [first, second, third] {
        produced.push(sequencer.store.block_at_id(id).await.unwrap().unwrap());
    }

    // A finalized floor, so the orphan report below cannot rewind past `first`.
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            finalized: vec![produced[0].clone()],
            ..empty_follow_update()
        },
    )
    .await;

    // The channel drops both, then puts the tip back on a parent we do not hold,
    // so it lands above the head instead of applying.
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            orphaned: produced[1..].iter().map(Clone::clone).collect(),
            adopted: vec![produced[2].clone()],
            ..empty_follow_update()
        },
    )
    .await;

    assert_eq!(
        sequencer.next_block_height().await,
        second,
        "the head rewound to the finalized floor"
    );
    assert_eq!(
        sequencer.store.published_high_water().await.unwrap(),
        Some(third),
        "a dropped orphan alongside it must not free the readopted height"
    );
    assert_eq!(
        sequencer.rewound_below_published().await,
        Some(third),
        "so the turn is still held"
    );
}

#[tokio::test]
async fn follow_update_records_deposits_for_the_production_drain() {
    let config = setup_sequencer_config();
    let (sequencer, mempool_handle) = start_sequencer(config).await;

    let recipient_id = initial_public_user_accounts()[0].account_id;
    let metadata = borsh::to_vec(&DepositMetadataForEncoding { recipient_id }).unwrap();
    let deposit = DepositInfo {
        op_id: [21; 32],
        tx_hash: TxHash::from([9; 32]),
        channel_id: ChannelId::from([0; 32]),
        inputs: Inputs::empty(),
        amount: 5,
        metadata: Metadata::try_from(metadata).expect("deposit metadata fits"),
        notes: DepositRecreatedNotes::default(),
    };

    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            deposits: vec![deposit],
            ..empty_follow_update()
        },
    )
    .await;

    let pending = sequencer.store.get_pending_deposit_events().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].deposit_op_id, HashType([21; 32]));
}

#[tokio::test]
async fn follow_adopted_peer_block_applies_and_persists() {
    let config = setup_sequencer_config();
    let (sequencer, mempool_handle) = start_sequencer(config).await;
    let genesis_meta = sequencer
        .store
        .latest_block_meta()
        .await
        .unwrap()
        .expect("genesis meta is set");

    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;
    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1,
        0,
        acc2,
        10,
        &create_signing_key_for_account1(),
    );
    let peer_block = common::test_utils::produce_dummy_block(2, Some(genesis_meta.hash), vec![tx]);

    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            adopted: vec![peer_block.clone()],
            ..empty_follow_update()
        },
    )
    .await;

    assert_eq!(sequencer.chain_height().await, 2);
    let stored = sequencer
        .store
        .block_at_id(2)
        .await
        .unwrap()
        .expect("adopted peer block should be persisted");
    assert_eq!(stored.header.hash, peer_block.header.hash);
    assert_eq!(
        sequencer
            .with_state(|s| s.get_account_by_id(acc2).balance)
            .await,
        20010
    );
}

#[tokio::test]
async fn follow_redelivery_of_own_block_is_deduped() {
    let config = setup_sequencer_config();
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;
    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1,
        0,
        acc2,
        10,
        &create_signing_key_for_account1(),
    );
    mempool_handle
        .push((TransactionOrigin::User, tx))
        .await
        .unwrap();
    sequencer.run_production_turn().await.unwrap();
    let block2 = sequencer.store.block_at_id(2).await.unwrap().unwrap();

    // The channel redelivers our own block under the MsgId the mock publisher
    // assigned at publish time.
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            adopted: vec![block2],
            ..empty_follow_update()
        },
    )
    .await;

    assert_eq!(sequencer.chain_height().await, 2);
    assert_eq!(
        sequencer
            .with_state(|s| s.get_account_by_id(acc2).balance)
            .await,
        20010,
        "the transfer must not be double-applied"
    );
}

#[tokio::test]
async fn follow_orphan_reverts_head_and_requeues_user_txs() {
    let config = setup_sequencer_config();
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;
    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1,
        0,
        acc2,
        10,
        &create_signing_key_for_account1(),
    );
    mempool_handle
        .push((TransactionOrigin::User, tx.clone()))
        .await
        .unwrap();
    sequencer.run_production_turn().await.unwrap();
    let block2 = sequencer.store.block_at_id(2).await.unwrap().unwrap();

    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            adopted: vec![],
            orphaned: vec![block2],
            ..empty_follow_update()
        },
    )
    .await;

    assert_eq!(sequencer.chain_height().await, 1);
    assert_eq!(
        sequencer
            .with_state(|s| s.get_account_by_id(acc1).balance)
            .await,
        10000,
        "the orphaned transfer must be reverted from the head"
    );
    let (origin, requeued) = sequencer
        .mempool
        .pop()
        .expect("orphaned user tx should be requeued");
    assert!(matches!(origin, TransactionOrigin::User));
    assert_eq!(requeued, tx);
    assert!(
        sequencer.mempool.pop().is_none(),
        "the clock tx must not be requeued"
    );
}

#[tokio::test]
async fn follow_orphan_of_a_finalized_block_requeues_nothing() {
    // The zone-sdk reports a block as orphaned once LIB pruning drops its
    // inscription from the channel lineage, which happens a poll or two after
    // every block of ours finalizes. Its transactions are irreversibly
    // included, so requeueing them would put them back in every block we
    // produce from then on.
    let config = setup_sequencer_config();
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;
    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1,
        0,
        acc2,
        10,
        &create_signing_key_for_account1(),
    );
    mempool_handle
        .push((TransactionOrigin::User, tx))
        .await
        .unwrap();
    sequencer.run_production_turn().await.unwrap();
    let block2 = sequencer.store.block_at_id(2).await.unwrap().unwrap();

    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            finalized: vec![block2.clone()],
            ..empty_follow_update()
        },
    )
    .await;
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            orphaned: vec![block2],
            ..empty_follow_update()
        },
    )
    .await;

    assert_eq!(
        sequencer.chain_height().await,
        2,
        "an irreversible block cannot be reverted"
    );
    assert_eq!(
        sequencer
            .with_state(|s| s.get_account_by_id(acc2).balance)
            .await,
        20010,
        "the finalized transfer stands"
    );
    assert!(
        sequencer.mempool.pop().is_none(),
        "a transaction that is already irreversible must not be requeued"
    );
}

#[tokio::test]
async fn follow_finalized_own_block_moves_final_tier_and_marks_store() {
    let config = setup_sequencer_config();
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    let tx = common::test_utils::produce_dummy_empty_transaction();
    mempool_handle
        .push((TransactionOrigin::User, tx))
        .await
        .unwrap();
    sequencer.run_production_turn().await.unwrap();
    let block2 = sequencer.store.block_at_id(2).await.unwrap().unwrap();

    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            adopted: vec![],
            orphaned: vec![],
            finalized: vec![block2],
            ..empty_follow_update()
        },
    )
    .await;

    let final_tip = sequencer
        .chain()
        .lock()
        .await
        .final_tip()
        .expect("final tip set");
    assert_eq!(final_tip.block_id, 2);
    assert_eq!(sequencer.chain_height().await, 2, "head is unchanged");
    let stored = sequencer.store.block_at_id(2).await.unwrap().unwrap();
    assert!(matches!(stored.bedrock_status, BedrockStatus::Finalized));
}

#[tokio::test]
async fn follow_finalized_delivery_drops_its_pending_record() {
    // The record exists to bridge the gap between the watcher's durable read
    // cursor and a block that carries the delivery. Once that block is
    // irreversible the delivery cannot be lost any more, so the record is owed
    // nothing and goes with the same update that made the block irreversible.
    let record = dispatch_record(17, ping_payload(b"settled"));
    let key = record.message_key;

    let (mut sequencer, mempool_handle) = start_sequencer(cross_zone_test_config()).await;
    sequencer
        .block_store()
        .storage_ref()
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![record],
        })
        .await
        .unwrap();

    let block_id = sequencer.run_production_turn().await.unwrap();
    let delivery_block = sequencer
        .store
        .block_at_id(block_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dispatches_in(&delivery_block), vec![key]);
    assert_eq!(
        pending_dispatches(&sequencer).await.len(),
        1,
        "including the delivery is not enough to settle its record"
    );

    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            finalized: vec![delivery_block],
            ..empty_follow_update()
        },
    )
    .await;

    assert!(
        pending_dispatches(&sequencer).await.is_empty(),
        "a delivery in an irreversible block settles its record"
    );
}

#[tokio::test]
async fn a_parked_finalized_block_does_not_drop_a_dispatch_record() {
    // Keyed by message key, not by height: a finalized block the final tier
    // parks never became irreversible, so nothing it happens to sit above may
    // settle a record. Dropping one here would lose the delivery for good, since
    // the watcher's floor has already moved past the peer block it came from.
    let record = dispatch_record(19, ping_payload(b"parked"));
    let key = record.message_key;
    let delivery = dispatch_tx(19, ping_payload(b"parked"));

    let (mut sequencer, mempool_handle) = start_sequencer(cross_zone_test_config()).await;
    sequencer
        .block_store()
        .storage_ref()
        .ask(AddPendingCrossZoneDispatches {
            dispatches: vec![record],
        })
        .await
        .unwrap();

    let tx = common::test_utils::produce_dummy_empty_transaction();
    mempool_handle
        .push((TransactionOrigin::User, tx))
        .await
        .unwrap();
    sequencer.run_production_turn().await.unwrap();

    // A skip-ahead block carrying the same delivery: not in head and linking to
    // nothing we hold, so the final tier parks it instead of applying it.
    let parked =
        common::test_utils::produce_dummy_block(9, Some(HashType([44; 32])), vec![delivery]);

    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            finalized: vec![parked],
            ..empty_follow_update()
        },
    )
    .await;

    assert_eq!(
        pending_dispatches(&sequencer)
            .await
            .iter()
            .map(|record| record.message_key)
            .collect::<Vec<_>>(),
        vec![key],
        "a parked finalized block must not drop its delivery's record"
    );
}

#[tokio::test]
async fn follow_finalized_backfill_block_is_applied_and_marked_finalized() {
    let config = setup_sequencer_config();
    let (sequencer, mempool_handle) = start_sequencer(config).await;
    let genesis_meta = sequencer
        .store
        .latest_block_meta()
        .await
        .unwrap()
        .expect("genesis meta is set");

    // A peer block we never saw as adopted arrives straight from the
    // finalized (backfill) stream.
    let peer_block = common::test_utils::produce_dummy_block(2, Some(genesis_meta.hash), vec![]);

    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            adopted: vec![],
            orphaned: vec![],
            finalized: vec![peer_block.clone()],
            ..empty_follow_update()
        },
    )
    .await;

    assert_eq!(
        sequencer.chain_height().await,
        2,
        "head mirrors final on backfill"
    );
    let stored = sequencer
        .store
        .block_at_id(2)
        .await
        .unwrap()
        .expect("backfilled block should be persisted");
    assert_eq!(stored.header.hash, peer_block.header.hash);
    assert!(matches!(stored.bedrock_status, BedrockStatus::Finalized));
}

#[tokio::test]
async fn parked_finalized_block_neither_sweeps_the_store_nor_drops_its_deposit_record() {
    let config = setup_sequencer_config();
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    // A produced block at head, still pending on the channel.
    let tx = common::test_utils::produce_dummy_empty_transaction();
    mempool_handle
        .push((TransactionOrigin::User, tx))
        .await
        .unwrap();
    sequencer.run_production_turn().await.unwrap();

    let deposit_op_id = HashType([21; 32]);
    let record = PendingDepositEventRecord {
        deposit_op_id,
        source_tx_hash: HashType([22; 32]),
        amount: 5,
        metadata: borsh::to_vec(&DepositMetadataForEncoding {
            recipient_id: initial_public_user_accounts()[0].account_id,
        })
        .unwrap(),
    };
    let deposit_tx = build_bridge_deposit_tx_from_event(&record).unwrap();
    assert!(
        sequencer
            .block_store()
            .storage_ref()
            .ask(AddPendingDepositEvent { event: record })
            .await
            .unwrap()
    );

    // Skip-ahead block carrying that deposit: not in head and linking to
    // nothing we hold, so the final tier parks it instead of applying it.
    let parked =
        common::test_utils::produce_dummy_block(9, Some(HashType([44; 32])), vec![deposit_tx]);

    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            adopted: vec![],
            orphaned: vec![],
            finalized: vec![parked],
            ..empty_follow_update()
        },
    )
    .await;

    // Nothing became irreversible, so the store must not be swept through the
    // parked block's height.
    let stored = sequencer.store.block_at_id(2).await.unwrap().unwrap();
    assert!(
        matches!(stored.bedrock_status, BedrockStatus::Pending),
        "a parked finalized block must not mark earlier blocks finalized"
    );
    // And its deposit is not minted anywhere, so dropping the record would lose
    // the deposit for good once the stall clears.
    assert!(
        sequencer
            .store
            .get_pending_deposit_events()
            .await
            .unwrap()
            .iter()
            .any(|event| event.deposit_op_id == deposit_op_id),
        "a parked finalized block must not drop its deposit record"
    );
}

#[tokio::test]
async fn restart_restores_head_tier_and_recovers_from_orphan() {
    let config = setup_sequencer_config();
    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;

    // Produce block 2 (a user transfer), then "crash" before it finalizes.
    let (storage_weak, tx, block2) = {
        let (mut sequencer, mempool_handle) = start_sequencer(config.clone()).await;
        let tx = common::test_utils::create_transaction_native_token_transfer(
            acc1,
            0,
            acc2,
            10,
            &create_signing_key_for_account1(),
        );
        mempool_handle
            .push((TransactionOrigin::User, tx.clone()))
            .await
            .unwrap();
        sequencer.run_production_turn().await.unwrap();
        let block2 = sequencer.store.block_at_id(2).await.unwrap().unwrap();
        (
            sequencer.block_store().storage_ref().downgrade(),
            tx,
            block2,
        )
    };
    storage_weak.wait_for_shutdown_with_result(|_| ()).await;

    // Restart: nothing is finalized, so block 2 must come back as *head*, not
    // final — the L1 can still orphan it.
    let (mut sequencer, mempool_handle) = start_sequencer(config.clone()).await;
    assert_eq!(sequencer.chain_height().await, 2);

    // The L1 orphans block 2 under its real MsgId (which we never persisted)
    // and adopts a competing empty block 2'.
    let genesis = sequencer.store.block_at_id(1).await.unwrap().unwrap();
    let block2_prime =
        common::test_utils::produce_dummy_block(2, Some(genesis.header.hash), vec![]);
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            adopted: vec![block2_prime.clone()],
            orphaned: vec![block2],
            ..empty_follow_update()
        },
    )
    .await;

    // The head reorged onto 2': transfer reverted, store overwritten, and the
    // orphaned user tx returned to the mempool.
    assert_eq!(sequencer.chain_height().await, 2);
    let head_tip = sequencer
        .chain()
        .lock()
        .await
        .head_tip()
        .expect("head tip set");
    assert_eq!(head_tip.hash, block2_prime.header.hash);
    assert_eq!(
        sequencer
            .with_state(|s| s.get_account_by_id(acc1).balance)
            .await,
        10000,
        "the orphaned transfer must be reverted"
    );
    let stored = sequencer.store.block_at_id(2).await.unwrap().unwrap();
    assert_eq!(stored.header.hash, block2_prime.header.hash);
    let (origin, requeued) = sequencer
        .mempool
        .pop()
        .expect("orphaned user tx should be requeued");
    assert!(matches!(origin, TransactionOrigin::User));
    assert_eq!(requeued, tx);
}

/// An orphan the same update puts back is on the head with its transactions
/// applied, so requeueing them would duplicate work the block already carries.
#[tokio::test]
async fn a_readopted_orphan_does_not_requeue_its_transactions() {
    let config = setup_sequencer_config();
    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1,
        0,
        acc2,
        10,
        &create_signing_key_for_account1(),
    );
    mempool_handle
        .push((TransactionOrigin::User, tx))
        .await
        .unwrap();
    sequencer.run_production_turn().await.unwrap();
    let block2 = sequencer.store.block_at_id(2).await.unwrap().unwrap();
    assert!(
        sequencer.mempool.pop().is_none(),
        "production must have drained the transaction into the block"
    );

    // The channel drops the block and puts the very same one back.
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            orphaned: vec![block2.clone()],
            adopted: vec![block2.clone()],
            ..empty_follow_update()
        },
    )
    .await;

    let head_tip = sequencer
        .chain()
        .lock()
        .await
        .head_tip()
        .expect("head tip set");
    assert_eq!(
        head_tip.hash, block2.header.hash,
        "the re-adopted block is back on the head"
    );
    assert!(
        sequencer.mempool.pop().is_none(),
        "a re-adopted block must not requeue its transactions"
    );
}

#[tokio::test]
async fn restart_reanchors_on_the_persisted_final_snapshot() {
    let config = setup_sequencer_config();

    // Produce block 2 and follow its finalization, which persists the final
    // snapshot; then "crash".
    let storage_weak = {
        let (mut sequencer, mempool_handle) = start_sequencer(config.clone()).await;
        let tx = common::test_utils::produce_dummy_empty_transaction();
        mempool_handle
            .push((TransactionOrigin::User, tx))
            .await
            .unwrap();
        sequencer.run_production_turn().await.unwrap();
        let block2 = sequencer.store.block_at_id(2).await.unwrap().unwrap();
        apply_follow_update(
            sequencer.block_store().storage_ref(),
            &sequencer.chain(),
            &mempool_handle,
            FollowUpdate {
                adopted: vec![],
                orphaned: vec![],
                finalized: vec![block2],
                ..empty_follow_update()
            },
        )
        .await;
        sequencer.block_store().storage_ref().downgrade()
    };
    storage_weak.wait_for_shutdown_with_result(|_| ()).await;

    // Restart: the final tier re-anchors on the snapshot instead of treating
    // the whole stored chain as final.
    let (sequencer, _mempool_handle) = start_sequencer(config.clone()).await;
    let chain = sequencer.chain();
    let chain = chain.lock().await;
    assert_eq!(chain.final_tip().expect("final tip set").block_id, 2);
    assert_eq!(chain.head_tip().expect("head tip set").block_id, 2);
}

#[tokio::test]
async fn record_produced_block_skips_persistence_on_lost_race() {
    let config = setup_sequencer_config();
    let (mut sequencer, _mempool_handle) = start_sequencer(config).await;
    let genesis_meta = sequencer
        .store
        .latest_block_meta()
        .await
        .unwrap()
        .expect("genesis meta is set");

    // A peer block wins height 2 while "our" block is in flight.
    let peer_block = common::test_utils::produce_dummy_block(2, Some(genesis_meta.hash), vec![]);
    sequencer.chain().lock().await.apply_adopted(&peer_block);

    // Our competing block at the same height: same parent, different content.
    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;
    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1,
        0,
        acc2,
        10,
        &create_signing_key_for_account1(),
    );
    let our_block = common::test_utils::produce_dummy_block(2, Some(genesis_meta.hash), vec![tx]);
    sequencer
        .record_produced_block(
            mock_msg_of(&our_block),
            our_block.clone(),
            vec![],
            &mock_checkpoint(),
        )
        .await
        .unwrap();

    // The lost-race block must not reach the store; the head keeps the peer block.
    assert!(sequencer.store.block_at_id(2).await.unwrap().is_none());
    let head_tip = sequencer.chain().lock().await.head_tip().expect("head tip");
    assert_eq!(head_tip.hash, peer_block.header.hash);
}

#[tokio::test]
async fn record_produced_block_skips_persistence_when_block_no_longer_chains() {
    let config = setup_sequencer_config();
    let (mut sequencer, _mempool_handle) = start_sequencer(config).await;

    // The head reorged under us: our block's parent is no longer the tip.
    let stale = common::test_utils::produce_dummy_block(2, Some(HashType([9; 32])), vec![]);
    sequencer
        .record_produced_block(
            mock_msg_of(&stale),
            stale.clone(),
            vec![],
            &mock_checkpoint(),
        )
        .await
        .unwrap();

    assert!(sequencer.store.block_at_id(2).await.unwrap().is_none());
    assert_eq!(sequencer.chain_height().await, 1, "head is unchanged");
}

#[tokio::test]
async fn follow_update_persists_blocks_meta_and_state_atomically() {
    let config = setup_sequencer_config();
    let (sequencer, mempool_handle) = start_sequencer(config).await;
    let genesis_meta = sequencer
        .store
        .latest_block_meta()
        .await
        .unwrap()
        .expect("genesis meta is set");

    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;
    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1,
        0,
        acc2,
        10,
        &create_signing_key_for_account1(),
    );
    let block2 = common::test_utils::produce_dummy_block(2, Some(genesis_meta.hash), vec![tx]);
    let block3 = common::test_utils::produce_dummy_block(3, Some(block2.header.hash), vec![]);

    // One update carrying several blocks: both adopted, block 2 also finalized.
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            adopted: vec![block2.clone(), block3.clone()],
            orphaned: vec![],
            finalized: vec![block2],
            ..empty_follow_update()
        },
    )
    .await;

    // Blocks, tip meta and state all reflect the end of the batch: a late
    // finalized entry for an earlier block must not drag the tip meta back.
    let meta = sequencer
        .store
        .latest_block_meta()
        .await
        .unwrap()
        .expect("meta is set");
    assert_eq!(meta.id, 3);
    assert_eq!(meta.hash, block3.header.hash);
    let stored2 = sequencer.store.block_at_id(2).await.unwrap().unwrap();
    assert!(matches!(stored2.bedrock_status, BedrockStatus::Finalized));
    let stored_balance = sequencer
        .store
        .get_lee_state()
        .await
        .unwrap()
        .expect("the store holds a chain")
        .get_account_by_id(acc2)
        .balance;
    assert_eq!(stored_balance, 20010);
}

/// Diagnostic repro: exercises `sequencer_stake`'s `Stake` instruction (claim
/// on the outer call, hand off to a mover chained call, self-chained confirm)
/// directly through `V03State::transition_from_public_transaction`, with no
/// sequencer/mempool/Bedrock machinery involved, to isolate whether the LEE
/// state machine itself claims the ownership account correctly.
#[test]
fn diag_sequencer_stake_claims_ownership_account() {
    let funding_key = PrivateKey::try_new([21; 32]).unwrap();
    let funding_id = AccountId::from(&PublicKey::new_from_private_key(&funding_key));
    let ownership_key = PrivateKey::try_new([22; 32]).unwrap();
    let ownership_id = AccountId::from(&PublicKey::new_from_private_key(&ownership_key));

    let amount: u128 = 5_000_000;
    let sequencer_key = test_sequencer_key(0x42);

    let config_id = system_accounts::sequencer_stake_config_account_id();
    let mut state = V03State::new()
        .with_programs([
            programs::authenticated_transfer(),
            programs::sequencer_stake(),
        ])
        .with_public_accounts([
            (
                funding_id,
                Account {
                    program_owner: programs::authenticated_transfer().id().into(),
                    balance: amount,
                    ..Account::default()
                },
            ),
            (config_id, system_accounts::sequencer_stake_config_account()),
        ]);

    assert_eq!(
        state.get_account_by_id(ownership_id),
        Account::default(),
        "ownership account must start out fresh/unclaimed"
    );

    let mover_instruction_data =
        Program::serialize_instruction(authenticated_transfer_core::Instruction::Transfer {
            amount,
        })
        .unwrap();

    let message = lee::public_transaction::Message::try_new(
        programs::sequencer_stake().id(),
        vec![
            funding_id,
            ownership_id,
            stake_funds_id(ownership_id),
            config_id,
        ],
        vec![Nonce(0), Nonce(0)],
        sequencer_stake_core::Instruction::Stake {
            sequencer_key,
            amount,
            mover_program_id: programs::authenticated_transfer().id(),
            mover_instruction_data,
        },
    )
    .unwrap();
    let witness_set =
        lee::public_transaction::WitnessSet::for_message(&message, &[&funding_key, &ownership_key]);
    let tx = PublicTransaction::new(message, witness_set);

    state
        .transition_from_public_transaction(&tx, 1, 0)
        .expect("Stake transaction should succeed");

    let ownership_account = state.get_account_by_id(ownership_id);
    assert_eq!(
        ownership_account.program_owner,
        programs::sequencer_stake().id().into(),
        "ownership account should be claimed by sequencer_stake"
    );
    assert_eq!(
        ownership_account.balance, 0,
        "the ownership account never custodies the stake"
    );

    let funds_account = state.get_account_by_id(stake_funds_id(ownership_id));
    assert_eq!(
        funds_account.program_owner,
        lee::AccountId::default(),
        "the funds PDA is balance-only, so nothing owns it; rule 5 guards the balance"
    );
    assert_eq!(funds_account.balance, amount);
}

/// The PDA custodying whatever `ownership_id` has staked.
fn stake_funds_id(ownership_id: AccountId) -> AccountId {
    sequencer_stake_core::stake_funds_account_id(programs::sequencer_stake().id(), &ownership_id)
}

/// Builds a `Stake` moving `amount` from `funding` into `ownership`'s stake
/// funds PDA via `authenticated_transfer`, taking each signer's nonce from
/// `state`.
fn stake_transaction(
    state: &V03State,
    funding: (AccountId, &PrivateKey),
    ownership: (AccountId, &PrivateKey),
    sequencer_key: sequencer_stake_core::SequencerKey,
    amount: u128,
) -> PublicTransaction {
    let (funding_id, funding_key) = funding;
    let (ownership_id, ownership_key) = ownership;
    let mover_instruction_data =
        Program::serialize_instruction(authenticated_transfer_core::Instruction::Transfer {
            amount,
        })
        .unwrap();

    let message = lee::public_transaction::Message::try_new(
        programs::sequencer_stake().id(),
        vec![
            funding_id,
            ownership_id,
            stake_funds_id(ownership_id),
            system_accounts::sequencer_stake_config_account_id(),
        ],
        vec![
            state.get_account_by_id(funding_id).nonce,
            state.get_account_by_id(ownership_id).nonce,
        ],
        sequencer_stake_core::Instruction::Stake {
            sequencer_key,
            amount,
            mover_program_id: programs::authenticated_transfer().id(),
            mover_instruction_data,
        },
    )
    .unwrap();
    let witness_set =
        lee::public_transaction::WitnessSet::for_message(&message, &[funding_key, ownership_key]);
    PublicTransaction::new(message, witness_set)
}

fn stake_entry(
    state: &V03State,
    sequencer_key: sequencer_stake_core::SequencerKey,
) -> Option<sequencer_stake_core::SequencerEntry> {
    sequencer_stake_core::SequencerStakeConfig::from_bytes(
        state
            .get_account_by_id(system_accounts::sequencer_stake_config_account_id())
            .data
            .as_ref(),
    )
    .expect("config account should decode")
    .entries
    .get(&sequencer_key)
    .copied()
}

/// A state carrying the two `sequencer_stake` needs plus a funding account
/// holding `funding_balance`.
fn stake_test_state(funding_id: AccountId, funding_balance: u128) -> V03State {
    V03State::new()
        .with_programs([
            programs::authenticated_transfer(),
            programs::sequencer_stake(),
        ])
        .with_public_accounts([
            (
                funding_id,
                Account {
                    program_owner: programs::authenticated_transfer().id().into(),
                    balance: funding_balance,
                    ..Account::default()
                },
            ),
            (
                system_accounts::sequencer_stake_config_account_id(),
                system_accounts::sequencer_stake_config_account(),
            ),
        ])
}

/// Builds an `UnstakeRequest` against `ownership`, passing `config_slot` where
/// the config account belongs.
fn unstake_request_transaction(
    state: &V03State,
    ownership: (AccountId, &PrivateKey),
    config_slot: AccountId,
    amount: u128,
    destination: AccountId,
) -> PublicTransaction {
    let (ownership_id, ownership_key) = ownership;
    let message = lee::public_transaction::Message::try_new(
        programs::sequencer_stake().id(),
        vec![ownership_id, config_slot],
        vec![state.get_account_by_id(ownership_id).nonce],
        sequencer_stake_core::Instruction::UnstakeRequest {
            amount,
            destination,
        },
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[ownership_key]);
    PublicTransaction::new(message, witness_set)
}

/// Anyone can credit a program-owned account, so an `UnstakeRequest` sized off
/// the balance rather than the tracked stake must be rejected.
#[test]
fn an_unstake_request_cannot_exceed_the_tracked_stake() {
    let funding_key = PrivateKey::try_new([31; 32]).unwrap();
    let funding_id = AccountId::from(&PublicKey::new_from_private_key(&funding_key));
    let ownership_key = PrivateKey::try_new([32; 32]).unwrap();
    let ownership_id = AccountId::from(&PublicKey::new_from_private_key(&ownership_key));

    let amount = system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE;
    let donation = 1;
    let sequencer_key = test_sequencer_key(0x43);

    let mut state = stake_test_state(funding_id, amount + donation);
    let stake = stake_transaction(
        &state,
        (funding_id, &funding_key),
        (ownership_id, &ownership_key),
        sequencer_key,
        amount,
    );
    state
        .transition_from_public_transaction(&stake, 1, 0)
        .expect("Stake should succeed");

    // Donate into the claimed funds PDA, which is where the stake actually
    // sits: a balance increase needs no ownership of the target.
    let funds_id = stake_funds_id(ownership_id);
    let message = lee::public_transaction::Message::try_new(
        programs::authenticated_transfer().id(),
        vec![funding_id, funds_id],
        vec![state.get_account_by_id(funding_id).nonce],
        authenticated_transfer_core::Instruction::Transfer { amount: donation },
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&funding_key]);
    state
        .transition_from_public_transaction(&PublicTransaction::new(message, witness_set), 2, 0)
        .expect("donation should succeed");

    let balance = state.get_account_by_id(funds_id).balance;
    assert_eq!(
        balance,
        amount + donation,
        "balance now exceeds total_staked"
    );

    let over = unstake_request_transaction(
        &state,
        (ownership_id, &ownership_key),
        system_accounts::sequencer_stake_config_account_id(),
        balance,
        funding_id,
    );
    state
        .transition_from_public_transaction(&over, 3, 0)
        .expect_err("an UnstakeRequest for the full balance must be rejected");

    // The tracked total is still releasable.
    let exact = unstake_request_transaction(
        &state,
        (ownership_id, &ownership_key),
        system_accounts::sequencer_stake_config_account_id(),
        amount,
        funding_id,
    );
    state
        .transition_from_public_transaction(&exact, 4, 0)
        .expect("an UnstakeRequest for the tracked stake should succeed");
}

#[test]
fn a_top_up_is_rejected_while_an_unstake_request_is_pending() {
    let funding_key = PrivateKey::try_new([33; 32]).unwrap();
    let funding_id = AccountId::from(&PublicKey::new_from_private_key(&funding_key));
    let ownership_key = PrivateKey::try_new([34; 32]).unwrap();
    let ownership_id = AccountId::from(&PublicKey::new_from_private_key(&ownership_key));

    let minimum = system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE;
    let sequencer_key = test_sequencer_key(0x44);

    let mut state = stake_test_state(funding_id, 3 * minimum);
    let stake = stake_transaction(
        &state,
        (funding_id, &funding_key),
        (ownership_id, &ownership_key),
        sequencer_key,
        2 * minimum,
    );
    state
        .transition_from_public_transaction(&stake, 1, 0)
        .expect("Stake should succeed");

    // Partial release, leaving exactly the minimum staked.
    let request = unstake_request_transaction(
        &state,
        (ownership_id, &ownership_key),
        system_accounts::sequencer_stake_config_account_id(),
        minimum,
        funding_id,
    );
    state
        .transition_from_public_transaction(&request, 2, 0)
        .expect("partial UnstakeRequest should succeed");

    let top_up = stake_transaction(
        &state,
        (funding_id, &funding_key),
        (ownership_id, &ownership_key),
        sequencer_key,
        minimum,
    );
    state
        .transition_from_public_transaction(&top_up, 3, 0)
        .expect_err("a top up must be rejected while an unstake request is pending");
}

/// Ownership accounts are `sequencer_stake`-owned too, so the config account is
/// identified by its address.
#[test]
fn an_ownership_account_cannot_stand_in_for_the_config_account() {
    let funding_key = PrivateKey::try_new([35; 32]).unwrap();
    let funding_id = AccountId::from(&PublicKey::new_from_private_key(&funding_key));
    let ownership_key = PrivateKey::try_new([36; 32]).unwrap();
    let ownership_id = AccountId::from(&PublicKey::new_from_private_key(&ownership_key));
    let other_ownership_key = PrivateKey::try_new([37; 32]).unwrap();
    let other_ownership_id =
        AccountId::from(&PublicKey::new_from_private_key(&other_ownership_key));

    let amount = system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE;
    let mut state = stake_test_state(funding_id, 2 * amount);

    for (index, (id, key, sequencer_key)) in [
        (ownership_id, &ownership_key, test_sequencer_key(0x45)),
        (
            other_ownership_id,
            &other_ownership_key,
            test_sequencer_key(0x46),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let stake = stake_transaction(
            &state,
            (funding_id, &funding_key),
            (id, key),
            sequencer_key,
            amount,
        );
        state
            .transition_from_public_transaction(
                &stake,
                u64::try_from(index).expect("test index fits") + 1,
                0,
            )
            .expect("Stake should succeed");
    }

    assert_eq!(
        state.get_account_by_id(other_ownership_id).program_owner,
        programs::sequencer_stake().id().into(),
        "the stand-in is owned by sequencer_stake, so ownership alone would not catch it"
    );

    let spoofed = unstake_request_transaction(
        &state,
        (ownership_id, &ownership_key),
        other_ownership_id,
        amount,
        funding_id,
    );
    state
        .transition_from_public_transaction(&spoofed, 3, 0)
        .expect_err("an ownership account passed as the config account must be rejected");
}

/// `FinalizeUnstake` drops a fully drained key's config entry, and the same
/// ownership account can stake again against it.
#[test]
fn a_fully_exited_ownership_account_can_stake_again() {
    let funding_key = PrivateKey::try_new([21; 32]).unwrap();
    let funding_id = AccountId::from(&PublicKey::new_from_private_key(&funding_key));
    let ownership_key = PrivateKey::try_new([22; 32]).unwrap();
    let ownership_id = AccountId::from(&PublicKey::new_from_private_key(&ownership_key));

    let amount = system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE;
    let sequencer_key = test_sequencer_key(0x42);

    let mut state = V03State::new()
        .with_programs([
            programs::authenticated_transfer(),
            programs::sequencer_stake(),
        ])
        .with_public_accounts([
            (
                funding_id,
                Account {
                    program_owner: programs::authenticated_transfer().id().into(),
                    balance: amount,
                    ..Account::default()
                },
            ),
            (
                system_accounts::sequencer_stake_config_account_id(),
                system_accounts::sequencer_stake_config_account(),
            ),
        ]);

    let stake = stake_transaction(
        &state,
        (funding_id, &funding_key),
        (ownership_id, &ownership_key),
        sequencer_key,
        amount,
    );
    state
        .transition_from_public_transaction(&stake, 1, 0)
        .expect("initial Stake should succeed");
    assert_eq!(
        stake_entry(&state, sequencer_key).map(|entry| entry.total_staked),
        Some(amount)
    );

    // Full exit, releasing back to the (now drained) funding account.
    let message = lee::public_transaction::Message::try_new(
        programs::sequencer_stake().id(),
        vec![
            ownership_id,
            system_accounts::sequencer_stake_config_account_id(),
        ],
        vec![state.get_account_by_id(ownership_id).nonce],
        sequencer_stake_core::Instruction::UnstakeRequest {
            amount,
            destination: funding_id,
        },
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&ownership_key]);
    state
        .transition_from_public_transaction(&PublicTransaction::new(message, witness_set), 2, 0)
        .expect("UnstakeRequest should succeed");

    let finalize = build_finalize_unstake_tx(
        ownership_id,
        sequencer_stake_core::PendingUnstake {
            amount,
            destination: funding_id,
        },
    )
    .unwrap();
    let LeeTransaction::Public(finalize) = finalize else {
        panic!("FinalizeUnstake should be a public transaction");
    };
    state
        .transition_from_public_transaction(&finalize, 3, 0)
        .expect("FinalizeUnstake should succeed");

    assert_eq!(stake_entry(&state, sequencer_key), None, "key fully exited");
    let funds_id = stake_funds_id(ownership_id);
    assert_eq!(
        state.get_account_by_id(funds_id).balance,
        0,
        "the funds PDA is drained"
    );
    assert_eq!(
        state.get_account_by_id(funding_id).balance,
        amount,
        "the destination received the released stake"
    );
    assert_eq!(state.get_account_by_id(ownership_id).balance, 0);
    assert_eq!(
        state.get_account_by_id(ownership_id).program_owner,
        programs::sequencer_stake().id().into(),
        "the ownership account stays claimed after a full exit"
    );

    // Both the ownership account and its funds PDA are still claimed, so the
    // re-stake goes through the same accounts rather than needing fresh ones.
    let restake = stake_transaction(
        &state,
        (funding_id, &funding_key),
        (ownership_id, &ownership_key),
        sequencer_key,
        amount,
    );
    state
        .transition_from_public_transaction(&restake, 4, 0)
        .expect("a fully exited account should be able to stake again");

    let entry = stake_entry(&state, sequencer_key).expect("key is registered again");
    assert_eq!(entry.account_id, ownership_id);
    assert_eq!(entry.total_staked, amount);
    assert_eq!(entry.total_pending_unstake, 0);
    assert_eq!(state.get_account_by_id(funds_id).balance, amount);
    assert_eq!(state.get_account_by_id(ownership_id).balance, 0);
}

#[test]
fn genesis_stakes_the_bootstrap_sequencer_at_the_configured_account() {
    let config = setup_sequencer_config();
    let bootstrap_sequencer_key = test_bootstrap_sequencer_key(&config);
    let (state, _genesis_txs) = build_genesis_state(&config, Some(bootstrap_sequencer_key));

    let stake_account = state.get_account_by_id(bootstrap_stake_account_id(&config));
    assert_eq!(
        stake_account.program_owner,
        programs::sequencer_stake().id().into()
    );
    assert_eq!(
        state
            .get_account_by_id(stake_funds_id(bootstrap_stake_account_id(&config)))
            .balance,
        system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE
    );

    let stake_config = sequencer_stake_core::SequencerStakeConfig::from_bytes(
        state
            .get_account_by_id(system_accounts::sequencer_stake_config_account_id())
            .data
            .as_ref(),
    )
    .expect("genesis config account should decode");
    assert_eq!(
        stake_config.entries[&bootstrap_sequencer_key].account_id,
        bootstrap_stake_account_id(&config)
    );
}

/// The genesis stake account must be one the operator can sign for, so the
/// bootstrap sequencer can top up and exit like any self-joined staker.
#[test]
fn the_bootstrap_sequencer_can_request_an_unstake_of_its_genesis_stake() {
    let config = setup_sequencer_config();
    let bootstrap_sequencer_key = test_bootstrap_sequencer_key(&config);
    let (mut state, _genesis_txs) = build_genesis_state(&config, Some(bootstrap_sequencer_key));

    let stake_id = bootstrap_stake_account_id(&config);
    let destination = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([56; 32]).unwrap(),
    ));

    let message = lee::public_transaction::Message::try_new(
        programs::sequencer_stake().id(),
        vec![
            stake_id,
            system_accounts::sequencer_stake_config_account_id(),
        ],
        // The genesis Stake transaction already signed once with this account.
        vec![Nonce(1)],
        sequencer_stake_core::Instruction::UnstakeRequest {
            amount: system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE,
            destination,
        },
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(
        &message,
        &[&bootstrap_stake_key(&config)],
    );
    let tx = PublicTransaction::new(message, witness_set);

    state
        .transition_from_public_transaction(&tx, 1, 0)
        .expect("the bootstrap sequencer should be able to request an unstake");

    let record = sequencer_stake_core::StakeRecord::from_bytes(
        state.get_account_by_id(stake_id).data.as_ref(),
    )
    .expect("genesis stake account should hold a StakeRecord");
    assert_eq!(
        record.pending_unstake.map(|pending| pending.amount),
        Some(system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE)
    );
}

/// The sink burned stakes land in.
fn slash_sink_id() -> AccountId {
    sequencer_stake_core::slash_sink_account_id(programs::sequencer_stake().id())
}

/// Stakes `amount` for a fresh key and returns everything a slash test needs.
fn slashable_state(
    amount: u128,
) -> (
    V03State,
    sequencer_stake_core::SequencerKey,
    AccountId,
    PrivateKey,
) {
    let funding_key = PrivateKey::try_new([41; 32]).unwrap();
    let funding_id = AccountId::from(&PublicKey::new_from_private_key(&funding_key));
    let ownership_key = PrivateKey::try_new([42; 32]).unwrap();
    let ownership_id = AccountId::from(&PublicKey::new_from_private_key(&ownership_key));
    let sequencer_key = test_sequencer_key(0x44);

    let mut state = stake_test_state(funding_id, amount);
    let stake = stake_transaction(
        &state,
        (funding_id, &funding_key),
        (ownership_id, &ownership_key),
        sequencer_key,
        amount,
    );
    state
        .transition_from_public_transaction(&stake, 1, 0)
        .expect("Stake should succeed");

    (state, sequencer_key, ownership_id, ownership_key)
}

/// An approval signed by `seed`'s Bedrock key.
fn test_approval(
    seed: u8,
    sequencer_key: sequencer_stake_core::SequencerKey,
) -> sequencer_stake_core::SlashApproval {
    let key = Ed25519Key::from_bytes(&[seed; 32]);
    let message = sequencer_stake_core::slash_approval_message(sequencer_key, TEST_INSCRIPTION);
    sequencer_stake_core::SlashApproval {
        signer: sequencer_stake_core::SequencerKey::new(key.public_key().to_bytes())
            .expect("a Bedrock public key is a valid Ed25519 public key"),
        signature: key.sign_payload(&message).to_bytes().to_vec(),
    }
}

fn slash_transaction(
    ownership_id: AccountId,
    sequencer_key: sequencer_stake_core::SequencerKey,
    approvals: Vec<sequencer_stake_core::SlashApproval>,
) -> PublicTransaction {
    let LeeTransaction::Public(tx) =
        crate::slashing::build_slash_tx(ownership_id, sequencer_key, TEST_INSCRIPTION, approvals)
            .expect("Slash tx should build")
    else {
        unreachable!("build_slash_tx builds a public transaction")
    };
    tx
}

#[test]
fn a_slash_burns_the_tracked_stake_to_the_sink() {
    let amount = system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE;
    let (mut state, sequencer_key, ownership_id, _ownership_key) = slashable_state(amount);

    let slash = slash_transaction(
        ownership_id,
        sequencer_key,
        vec![test_approval(0x44, sequencer_key)],
    );
    state
        .transition_from_public_transaction(&slash, 2, 0)
        .expect("Slash should succeed");

    assert_eq!(
        state
            .get_account_by_id(stake_funds_id(ownership_id))
            .balance,
        0
    );
    assert_eq!(state.get_account_by_id(slash_sink_id()).balance, amount);
    assert_eq!(stake_entry(&state, sequencer_key), None);

    // A replay has no entry left to burn.
    assert!(
        state
            .transition_from_public_transaction(&slash, 3, 0)
            .is_err()
    );
}

#[test]
fn a_slash_claws_back_a_pending_unstake() {
    let amount = system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE;
    let (mut state, sequencer_key, ownership_id, ownership_key) = slashable_state(amount);
    let destination = AccountId::new([77; 32]);

    let unstake = unstake_request_transaction(
        &state,
        (ownership_id, &ownership_key),
        system_accounts::sequencer_stake_config_account_id(),
        amount,
        destination,
    );
    state
        .transition_from_public_transaction(&unstake, 2, 0)
        .expect("UnstakeRequest should succeed");

    let slash = slash_transaction(
        ownership_id,
        sequencer_key,
        vec![test_approval(0x44, sequencer_key)],
    );
    state
        .transition_from_public_transaction(&slash, 3, 0)
        .expect("Slash should succeed");

    // The pending release burned with the rest; nothing is left to finalize.
    assert_eq!(state.get_account_by_id(slash_sink_id()).balance, amount);
    assert_eq!(
        state
            .get_account_by_id(stake_funds_id(ownership_id))
            .balance,
        0
    );
    let LeeTransaction::Public(finalize) = build_finalize_unstake_tx(
        ownership_id,
        sequencer_stake_core::PendingUnstake {
            amount,
            destination,
        },
    )
    .unwrap() else {
        unreachable!("build_finalize_unstake_tx builds a public transaction")
    };
    assert!(
        state
            .transition_from_public_transaction(&finalize, 4, 0)
            .is_err()
    );
}

#[test]
fn a_slash_without_enough_approvals_is_rejected() {
    let amount = system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE;
    let (mut state, sequencer_key, ownership_id, _ownership_key) = slashable_state(amount);

    // No signatures, no authorization.
    let unapproved = slash_transaction(ownership_id, sequencer_key, Vec::new());
    assert!(
        state
            .transition_from_public_transaction(&unapproved, 2, 0)
            .is_err()
    );

    // An unaccredited signer counts for nothing.
    let outsider = slash_transaction(
        ownership_id,
        sequencer_key,
        vec![test_approval(0x55, sequencer_key)],
    );
    assert!(
        state
            .transition_from_public_transaction(&outsider, 2, 0)
            .is_err()
    );

    // Nor an accredited signer over a different inscription.
    let mut wrong_inscription = test_approval(0x44, sequencer_key);
    wrong_inscription.signature = {
        let key = Ed25519Key::from_bytes(&[0x44; 32]);
        let message = sequencer_stake_core::slash_approval_message(sequencer_key, [0xFF; 32]);
        key.sign_payload(&message).to_bytes().to_vec()
    };
    let mismatched = slash_transaction(ownership_id, sequencer_key, vec![wrong_inscription]);
    assert!(
        state
            .transition_from_public_transaction(&mismatched, 2, 0)
            .is_err()
    );

    assert_eq!(
        state
            .get_account_by_id(stake_funds_id(ownership_id))
            .balance,
        amount
    );
    assert_eq!(state.get_account_by_id(slash_sink_id()).balance, 0);
}

/// The route struct refuses unknown keys, so a misspelled `mint_cap` in an
/// operator config fails startup instead of silently seeding uncapped.
#[test]
fn a_misspelled_mint_cap_key_fails_route_parse() {
    let route = serde_json::from_value::<CrossZoneRoute>(serde_json::json!({
        "src_program_id": [0, 0, 0, 0, 0, 0, 0, 1],
        "target_program_id": [0, 0, 0, 0, 0, 0, 0, 2],
        "mintcap": 1_000,
    }));
    assert!(route.is_err(), "an unknown key must fail the parse");
}

/// Gating is atomic: no `cross_zone`, no cross-zone genesis transaction;
/// empty-peers carries exactly the four `InitConfig`s, in order.
#[test]
fn genesis_cross_zone_transactions_follow_the_declaration() {
    let cross_zone_ids = [
        programs::cross_zone_inbox().id(),
        programs::cross_zone_outbox().id(),
        programs::ping_sender().id(),
        programs::ping_receiver().id(),
        programs::bridge_lock().id(),
        programs::wrapped_token().id(),
    ];
    let tx_program = |tx: &LeeTransaction| match tx {
        LeeTransaction::Public(public) => public.message().program_id,
        LeeTransaction::PrivacyPreserving(_) | LeeTransaction::ProgramDeployment(_) => {
            unreachable!("genesis holds only public transactions")
        }
    };

    let temp_dir = tempdir().unwrap();
    let mut config = setup_sequencer_config();
    config.home = temp_dir.path().to_path_buf();
    let key = test_bootstrap_sequencer_key(&config);
    let (state, txs) = build_genesis_state(&config, Some(key));
    assert!(
        !txs.iter()
            .any(|tx| cross_zone_ids.contains(&tx_program(tx))),
        "a configless genesis must carry no cross-zone transaction"
    );
    for id in cross_zone_ids {
        assert!(state.get_program(id).is_none());
    }

    let temp_dir = tempdir().unwrap();
    let mut config = setup_sequencer_config();
    config.home = temp_dir.path().to_path_buf();
    config.cross_zone = Some(config::CrossZoneConfig {
        peers: Vec::new(),
        source_authority: None,
        source_governance: None,
    });
    let key = test_bootstrap_sequencer_key(&config);
    let (state, txs) = build_genesis_state(&config, Some(key));
    let cross_zone_txs: Vec<_> = txs
        .iter()
        .map(tx_program)
        .filter(|id| cross_zone_ids.contains(id))
        .collect();
    assert_eq!(
        cross_zone_txs,
        vec![
            programs::wrapped_token().id(),
            programs::ping_sender().id(),
            programs::ping_receiver().id(),
            programs::bridge_lock().id(),
            programs::cross_zone_inbox().id(),
        ],
        "the four InitConfigs then the inbox config, in the fixed order"
    );
    for id in cross_zone_ids {
        assert!(state.get_program(id).is_some());
    }
}
