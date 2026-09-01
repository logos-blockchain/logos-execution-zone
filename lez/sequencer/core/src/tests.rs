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
    Account, AccountId, Data, PrivateKey, PublicKey, PublicTransaction, V03State, program::Program,
};
use lee_core::{
    BlockId,
    account::Nonce,
    program::{PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, ProgramId},
};
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
    MAX_DISPATCHES_PER_BLOCK, RETIRE_DISPATCH_AFTER_FAILURES, TransactionOrigin,
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
    mock::{SequencerCoreWithMockClients, mock_checkpoint},
    resubmittable_txs,
};

mod reconstruction;

/// The peer zone a cross-zone test receives from. Distinct from the test
/// channel id (`[0; 32]`), which the inbox guest rejects as a source.
const PEER_ZONE: [u8; 32] = [0xbe_u8; 32];

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
    SequencerCoreWithMockClients::start_from_config(config, storage_ref, Vec::new()).await
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
            priority_fee: config::default_priority_fee(),
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
    assert!(is_sequencer_only_program(
        program_loader_core::immutable_deploy_account_id(programs::cross_zone_inbox().id())
    ));
    assert!(!is_sequencer_only_program(
        program_loader_core::immutable_deploy_account_id(programs::cross_zone_outbox().id())
    ));
    assert!(!is_sequencer_only_program(
        program_loader_core::immutable_deploy_account_id(programs::wrapped_token().id())
    ));
    assert!(!is_sequencer_only_program(
        program_loader_core::immutable_deploy_account_id(programs::ping_sender().id())
    ));
    assert!(!is_sequencer_only_program(
        program_loader_core::immutable_deploy_account_id(programs::clock().id())
    ));
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

    if public_tx.message.program_account_id
        != program_loader_core::immutable_deploy_account_id(programs::bridge().id())
    {
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
                    src_account_id: program_loader_core::immutable_deploy_account_id(
                        programs::ping_sender().id(),
                    ),
                    target_account_id: program_loader_core::immutable_deploy_account_id(
                        programs::ping_receiver().id(),
                    ),
                }],
                expected_block_signing_pubkeys: Vec::new(),
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
    let receiver_account_id = programs::ping_receiver().deployed_account_id();
    LeeTransaction::Public(cross_zone::build_dispatch_from_emission(
        &cross_zone::EmissionSource {
            src_zone: PEER_ZONE,
            src_block_id,
            src_block_hash: peer_block_hash(src_block_id),
            src_tx_index: 0,
            src_account_id: program_loader_core::immutable_deploy_account_id(
                programs::ping_sender().id(),
            ),
        },
        receiver_id,
        &[
            receiver_config_account_id(receiver_account_id).into_value(),
            ping_record_pda(receiver_account_id).into_value(),
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
    let (genesis_state, genesis_txs) = build_genesis_state(&config, Some(bootstrap_sequencer_key), &[]);
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
            orphaned: vec![(MsgId::from(minted_block.header.hash.0), minted_block)],
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
    let vault_id =
        vault_core::compute_vault_account_id(programs::vault().deployed_account_id(), recipient_id);
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

    let vault_id =
        vault_core::compute_vault_account_id(programs::vault().deployed_account_id(), recipient_id);
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
    // durable read cursor and a block carrying the dispatch survivable.
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

    let record_id = ping_record_pda(programs::ping_receiver().deployed_account_id());
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
    assert!(dead_letters[0].transaction_bytes > 0);
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
            finalized: vec![(MsgId::from(delivery_block.header.hash.0), delivery_block)],
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

    let result = sequencer.build_block_from_mempool(Some(&[])).await;
    assert!(result.is_ok());
    // Building itself does not advance the head; only apply-after-publish does.
    assert_eq!(sequencer.chain_height().await, genesis_height);
}

#[tokio::test]
async fn a_stake_only_moves_the_committee_once_it_has_finalized() {
    // Genesis stakes the bootstrap key, so the head wants it accredited already.
    let (mut sequencer, mempool_handle) = common_setup().await;

    assert!(
        sequencer
            .build_block_from_mempool(Some(&[]))
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
            finalized: vec![(MsgId::from(genesis.header.hash.0), genesis)],
            ..empty_follow_update()
        },
    )
    .await;

    let wanted = sequencer
        .build_block_from_mempool(Some(&[]))
        .await
        .unwrap()
        .committee_update
        .expect("the stake is irreversible now, so the committee should follow it");
    assert!(
        sequencer
            .build_block_from_mempool(Some(&wanted))
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
    let absence = crate::committee_discovery::CommitteeAbsence::default();
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
        &absence,
        None
    ));
    assert!(finalize_unstake_is_includable(
        &state,
        &common::test_utils::produce_dummy_empty_transaction(),
        &absence,
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
            program_loader_core::immutable_deploy_account_id(programs::clock().id()),
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
    // Deploy the clock_chain_caller test program: one signed NewSegment per chunk (tail-to-head),
    // then a signed UploadHeader — each its own transaction and production turn.
    let bytecode = clock_chain_caller.elf().to_vec();
    let chunks: Vec<&[u8]> = bytecode
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
        .collect();
    let segment_keys: Vec<PrivateKey> = (0..chunks.len())
        .map(|i| PrivateKey::try_new([160 + u8::try_from(i).unwrap(); 32]).unwrap())
        .collect();
    let segment_ids: Vec<AccountId> = segment_keys
        .iter()
        .map(|key| AccountId::from(&PublicKey::new_from_private_key(key)))
        .collect();
    let header_key = PrivateKey::try_new([179; 32]).unwrap();
    let clock_chain_caller_header = AccountId::from(&PublicKey::new_from_private_key(&header_key));

    for (i, chunk) in chunks.iter().enumerate().rev() {
        let next_segment = segment_ids.get(i + 1).copied();
        let mut account_ids = vec![segment_ids[i]];
        account_ids.extend(next_segment);
        let segment_message = lee::public_transaction::Message::try_new(
            PROGRAM_LOADER_ACCOUNT_ID,
            account_ids,
            vec![Nonce(0)],
            program_loader_core::Instruction::WriteSegment {
                bytecode: (*chunk).to_vec(),
                next_segment,
            },
        )
        .unwrap();
        let segment_tx = LeeTransaction::Public(PublicTransaction::new(
            segment_message.clone(),
            lee::public_transaction::WitnessSet::for_message(&segment_message, &[&segment_keys[i]]),
        ));
        mempool_handle
            .push((TransactionOrigin::User, segment_tx))
            .await
            .unwrap();
        sequencer.run_production_turn().await.unwrap();
    }

    let mut header_account_ids = vec![clock_chain_caller_header];
    header_account_ids.extend(segment_ids.iter().copied());
    let header_message = lee::public_transaction::Message::try_new(
        PROGRAM_LOADER_ACCOUNT_ID,
        header_account_ids,
        vec![Nonce(0)],
        program_loader_core::Instruction::CreateHeader {
            first_segment: segment_ids[0],
            immutable: true,
        },
    )
    .unwrap();
    let header_tx = LeeTransaction::Public(PublicTransaction::new(
        header_message.clone(),
        lee::public_transaction::WitnessSet::for_message(&header_message, &[&header_key]),
    ));
    mempool_handle
        .push((TransactionOrigin::User, header_tx))
        .await
        .unwrap();
    sequencer.run_production_turn().await.unwrap();

    // Build a user transaction that invokes clock_chain_caller, which in turn chain-calls the
    // clock program with the clock accounts. The sequencer should detect that the resulting
    // state diff modifies clock accounts and drop the transaction.
    let clock_program_id = programs::clock().id();
    let timestamp: u64 = 0;

    let message = lee::public_transaction::Message::try_new(
        clock_chain_caller_header,
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
//         program_owner: programs::authenticated_transfer().deployed_account_id(),
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
    let program_id = test_programs::time_locked_transfer().deployed_account_id();
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
            program_owner: programs::authenticated_transfer().deployed_account_id(),
            ..Account::default()
        },
    );

    let key1 = PrivateKey::try_new([1; 32]).unwrap();
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&key1));
    state.force_insert_account(
        sender_id,
        Account {
            program_owner: test_programs::time_locked_transfer().deployed_account_id(),
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
            program_owner: programs::authenticated_transfer().deployed_account_id(),
            ..Account::default()
        },
    );

    let key1 = PrivateKey::try_new([1; 32]).unwrap();
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&key1));
    state.force_insert_account(
        sender_id,
        Account {
            program_owner: test_programs::time_locked_transfer().deployed_account_id(),
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

fn pinata_cooldown_data(prize: u128, cooldown_ms: u64, last_claim_timestamp: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&prize.to_le_bytes());
    buf.extend_from_slice(&cooldown_ms.to_le_bytes());
    buf.extend_from_slice(&last_claim_timestamp.to_le_bytes());
    buf
}

fn pinata_cooldown_transaction(
    pinata_id: AccountId,
    winner_id: AccountId,
    clock_account_id: AccountId,
) -> PublicTransaction {
    let program_id = test_programs::pinata_cooldown().deployed_account_id();
    let message = lee::public_transaction::Message::try_new(
        program_id,
        vec![pinata_id, winner_id, clock_account_id],
        vec![],
        (),
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[]);
    PublicTransaction::new(message, witness_set)
}

#[test]
fn pinata_cooldown_claim_succeeds_after_cooldown() {
    let winner_id = AccountId::new([11; 32]);
    let pinata_id = AccountId::new([99; 32]);

    let genesis_timestamp = 1000;
    let prize = 50;
    let cooldown_ms = 500;
    // Last claim was at genesis, so any timestamp >= genesis + cooldown should work.
    let last_claim_timestamp = genesis_timestamp;

    // Advance the clock so the cooldown check reads an updated timestamp.
    let block_timestamp = genesis_timestamp + cooldown_ms;
    let mut state = state_with_clock_and_program(test_programs::pinata_cooldown(), block_timestamp);

    // The winner must be a non-default account so the program may credit it without claiming.
    state.force_insert_account(
        winner_id,
        Account {
            program_owner: programs::authenticated_transfer().deployed_account_id(),
            ..Account::default()
        },
    );
    state.force_insert_account(
        pinata_id,
        Account {
            program_owner: test_programs::pinata_cooldown().deployed_account_id(),
            balance: 1000,
            data: pinata_cooldown_data(prize, cooldown_ms, last_claim_timestamp)
                .try_into()
                .unwrap(),
            ..Account::default()
        },
    );

    let tx = pinata_cooldown_transaction(
        pinata_id,
        winner_id,
        system_accounts::clock_account_ids()[0],
    );

    state
        .transition_from_public_transaction(&tx, 2, block_timestamp)
        .unwrap();

    assert_eq!(state.get_account_by_id(pinata_id).balance, 1000 - prize);
    assert_eq!(state.get_account_by_id(winner_id).balance, prize);
}

#[test]
fn pinata_cooldown_claim_fails_during_cooldown() {
    let winner_id = AccountId::new([11; 32]);
    let pinata_id = AccountId::new([99; 32]);

    let genesis_timestamp = 1000;
    let prize = 50;
    let cooldown_ms = 500;
    let last_claim_timestamp = genesis_timestamp;

    // Timestamp is only 100ms after the last claim, well within the 500ms cooldown.
    let block_timestamp = genesis_timestamp + 100;
    let mut state = state_with_clock_and_program(test_programs::pinata_cooldown(), block_timestamp);

    state.force_insert_account(
        winner_id,
        Account {
            program_owner: programs::authenticated_transfer().deployed_account_id(),
            ..Account::default()
        },
    );
    state.force_insert_account(
        pinata_id,
        Account {
            program_owner: test_programs::pinata_cooldown().deployed_account_id(),
            balance: 1000,
            data: pinata_cooldown_data(prize, cooldown_ms, last_claim_timestamp)
                .try_into()
                .unwrap(),
            ..Account::default()
        },
    );

    let tx = pinata_cooldown_transaction(
        pinata_id,
        winner_id,
        system_accounts::clock_account_ids()[0],
    );

    let result = state.transition_from_public_transaction(&tx, 2, block_timestamp);

    assert!(result.is_err(), "Claim should fail during cooldown period");
    assert_eq!(state.get_account_by_id(pinata_id).balance, 1000);
    assert_eq!(state.get_account_by_id(winner_id).balance, 0);
}

#[test]
fn pda_mechanism_with_pinata_token_program() {
    let pinata_token = programs::pinata_token();
    let token = programs::token();

    let pinata_definition_id = AccountId::new([1; 32]);
    let pinata_token_definition_id = AccountId::new([2; 32]);
    // Total supply of pinata token will be in an account under a PDA.
    let pinata_token_holding_id =
        AccountId::for_public_pda(&pinata_token.deployed_account_id(), &PdaSeed::new([0; 32]));
    let winner_token_holding_id = AccountId::new([3; 32]);

    let expected_winner_account_holding = token_core::TokenHolding::Fungible {
        definition_id: pinata_token_definition_id,
        balance: 150,
    };
    let expected_winner_token_holding_post = Account {
        program_owner: token.deployed_account_id(),
        data: Data::from(&expected_winner_account_holding),
        ..Account::default()
    };

    // Register the pinata-token and token programs and create the pinata definition account.
    // This replaces the removed `add_pinata_token_program` helper.
    let mut state = V03State::new().with_programs([pinata_token.clone(), token.clone()]);
    state.force_insert_account(
        pinata_definition_id,
        Account {
            program_owner: pinata_token.deployed_account_id(),
            // Difficulty: 3
            data: vec![3; 33].try_into().unwrap(),
            ..Account::default()
        },
    );

    // Set up the token accounts directly (bypassing public transactions which
    // would require signers for Claim::Authorized). The focus of this test is
    // the PDA mechanism in the pinata program's chained call, not token creation.
    let total_supply: u128 = 10_000_000;
    let token_definition = token_core::TokenDefinition::Fungible {
        name: String::from("PINATA"),
        total_supply,
        metadata_id: None,
    };
    let token_holding = token_core::TokenHolding::Fungible {
        definition_id: pinata_token_definition_id,
        balance: total_supply,
    };
    let winner_holding = token_core::TokenHolding::Fungible {
        definition_id: pinata_token_definition_id,
        balance: 0,
    };
    state.force_insert_account(
        pinata_token_definition_id,
        Account {
            program_owner: token.deployed_account_id(),
            data: Data::from(&token_definition),
            ..Account::default()
        },
    );
    state.force_insert_account(
        pinata_token_holding_id,
        Account {
            program_owner: token.deployed_account_id(),
            data: Data::from(&token_holding),
            ..Account::default()
        },
    );
    state.force_insert_account(
        winner_token_holding_id,
        Account {
            program_owner: token.deployed_account_id(),
            data: Data::from(&winner_holding),
            ..Account::default()
        },
    );

    // Submit a solution to the pinata program to claim the prize
    let solution: u128 = 989_106;
    let message = lee::public_transaction::Message::try_new(
        pinata_token.deployed_account_id(),
        vec![
            pinata_definition_id,
            pinata_token_holding_id,
            winner_token_holding_id,
        ],
        vec![],
        solution,
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);
    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    let winner_token_holding_post = state.get_account_by_id(winner_token_holding_id);
    assert_eq!(
        winner_token_holding_post,
        expected_winner_token_holding_post
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
            program_loader_core::immutable_deploy_account_id(programs::bridge().id()),
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
            adopted: vec![(MsgId::from([1; 32]), peer_block)],
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

/// The channel orphaning our own still-unfinalized blocks rewinds the head and
/// prunes them from the store, so nothing in the chain state remembers we ever
/// produced them. Producing again there would put a second, different block at
/// a height the channel already carries — the fork that has to be prevented.
#[tokio::test]
async fn head_rewound_below_published_height_blocks_production() {
    let config = setup_sequencer_config();
    let (mut sequencer, mempool_handle) = start_sequencer(config).await;

    let first = sequencer.run_production_turn().await.unwrap();
    let published_tip = sequencer.run_production_turn().await.unwrap();
    assert_eq!(
        sequencer.store.published_high_water().await.unwrap(),
        Some(published_tip),
        "publishing records the high water mark"
    );
    assert!(
        sequencer.rewound_below_published().await.is_none(),
        "an intact head is free to produce"
    );

    let mut produced: Vec<Block> = Vec::new();
    for id in [first, published_tip] {
        produced.push(sequencer.store.block_at_id(id).await.unwrap().unwrap());
    }

    // The sdk reports both of them as orphaned.
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            orphaned: produced
                .iter()
                .map(|block| (MsgId::from([0_u8; 32]), block.clone()))
                .collect(),
            ..empty_follow_update()
        },
    )
    .await;

    assert!(
        sequencer
            .store
            .latest_block_meta()
            .await
            .unwrap()
            .unwrap()
            .id
            < published_tip,
        "the orphan report rewound the stored tip"
    );
    assert_eq!(
        sequencer.rewound_below_published().await,
        Some(published_tip),
        "the mark outlives the pruning and blocks the turn"
    );

    // Those inscriptions were on the channel all along: finalizing them rebases
    // the head onto them, and production is free again. The guard is a wait.
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            finalized: produced
                .iter()
                .map(|block| (MsgId::from([1_u8; 32]), block.clone()))
                .collect(),
            ..empty_follow_update()
        },
    )
    .await;

    assert_eq!(sequencer.next_block_height().await, published_tip + 1);
    assert!(
        sequencer.rewound_below_published().await.is_none(),
        "a recovered head resumes producing"
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
            adopted: vec![(MsgId::from([1; 32]), peer_block.clone())],
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
            adopted: vec![(MsgId::from(block2.header.hash.0), block2)],
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
            orphaned: vec![(MsgId::from(block2.header.hash.0), block2)],
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
            finalized: vec![(MsgId::from(block2.header.hash.0), block2.clone())],
            ..empty_follow_update()
        },
    )
    .await;
    apply_follow_update(
        sequencer.block_store().storage_ref(),
        &sequencer.chain(),
        &mempool_handle,
        FollowUpdate {
            orphaned: vec![(MsgId::from(block2.header.hash.0), block2)],
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
            finalized: vec![(MsgId::from(block2.header.hash.0), block2)],
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
            finalized: vec![(MsgId::from(delivery_block.header.hash.0), delivery_block)],
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
            finalized: vec![(MsgId::from([9; 32]), parked)],
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
            finalized: vec![(MsgId::from([2; 32]), peer_block.clone())],
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
            finalized: vec![(MsgId::from([9; 32]), parked)],
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
            adopted: vec![(MsgId::from([21; 32]), block2_prime.clone())],
            orphaned: vec![(MsgId::from([20; 32]), block2)],
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
                finalized: vec![(MsgId::from(block2.header.hash.0), block2)],
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
    sequencer
        .chain()
        .lock()
        .await
        .apply_adopted(MsgId::from([9; 32]), &peer_block);

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
            MsgId::from(our_block.header.hash.0),
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
            MsgId::from(stale.header.hash.0),
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
            adopted: vec![
                (MsgId::from([2; 32]), block2.clone()),
                (MsgId::from([3; 32]), block3.clone()),
            ],
            orphaned: vec![],
            finalized: vec![(MsgId::from([2; 32]), block2)],
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
                    program_owner: programs::authenticated_transfer().deployed_account_id(),
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
        program_loader_core::immutable_deploy_account_id(programs::sequencer_stake().id()),
        vec![funding_id, ownership_id, config_id],
        vec![Nonce(0), Nonce(0)],
        sequencer_stake_core::Instruction::Stake {
            sequencer_key,
            amount,
            mover_account_id: program_loader_core::immutable_deploy_account_id(
                programs::authenticated_transfer().id(),
            ),
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
        program_loader_core::immutable_deploy_account_id(programs::sequencer_stake().id()),
        "ownership account should be claimed by sequencer_stake"
    );
    assert_eq!(ownership_account.balance, amount);
}

/// Builds a `Stake` moving `amount` from `funding` into `ownership` via
/// `authenticated_transfer`, taking each signer's nonce from `state`.
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
        program_loader_core::immutable_deploy_account_id(programs::sequencer_stake().id()),
        vec![
            funding_id,
            ownership_id,
            system_accounts::sequencer_stake_config_account_id(),
        ],
        vec![
            state.get_account_by_id(funding_id).nonce,
            state.get_account_by_id(ownership_id).nonce,
        ],
        sequencer_stake_core::Instruction::Stake {
            sequencer_key,
            amount,
            mover_account_id: program_loader_core::immutable_deploy_account_id(
                programs::authenticated_transfer().id(),
            ),
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
                    program_owner: programs::authenticated_transfer().deployed_account_id(),
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
        program_loader_core::immutable_deploy_account_id(programs::sequencer_stake().id()),
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

    // Donate into the claimed ownership account: a balance increase needs no
    // ownership of the target.
    let message = lee::public_transaction::Message::try_new(
        programs::authenticated_transfer().deployed_account_id(),
        vec![funding_id, ownership_id],
        vec![state.get_account_by_id(funding_id).nonce],
        authenticated_transfer_core::Instruction::Transfer { amount: donation },
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&funding_key]);
    state
        .transition_from_public_transaction(&PublicTransaction::new(message, witness_set), 2, 0)
        .expect("donation should succeed");

    let balance = state.get_account_by_id(ownership_id).balance;
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
        program_loader_core::immutable_deploy_account_id(programs::sequencer_stake().id()),
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
                    program_owner: programs::authenticated_transfer().deployed_account_id(),
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
        program_loader_core::immutable_deploy_account_id(programs::sequencer_stake().id()),
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
    assert_eq!(state.get_account_by_id(ownership_id).balance, 0);
    assert_eq!(
        state.get_account_by_id(ownership_id).program_owner,
        program_loader_core::immutable_deploy_account_id(programs::sequencer_stake().id()),
        "the ownership account stays claimed after a full exit"
    );

    // The account is still claimed, so the re-stake goes through the same
    // already-owned account rather than needing a fresh one.
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
    assert_eq!(state.get_account_by_id(ownership_id).balance, amount);
}

#[test]
fn genesis_stakes_the_bootstrap_sequencer_at_the_configured_account() {
    let config = setup_sequencer_config();
    let bootstrap_sequencer_key = test_bootstrap_sequencer_key(&config);
    let (state, _genesis_txs) = build_genesis_state(&config, Some(bootstrap_sequencer_key), &[]);

    let stake_account = state.get_account_by_id(bootstrap_stake_account_id(&config));
    assert_eq!(
        stake_account.program_owner,
        program_loader_core::immutable_deploy_account_id(programs::sequencer_stake().id())
    );
    assert_eq!(
        stake_account.balance,
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
    let (mut state, _genesis_txs) = build_genesis_state(&config, Some(bootstrap_sequencer_key), &[]);

    let stake_id = bootstrap_stake_account_id(&config);
    let destination = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([56; 32]).unwrap(),
    ));

    let message = lee::public_transaction::Message::try_new(
        program_loader_core::immutable_deploy_account_id(programs::sequencer_stake().id()),
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

/// Uploads `bytecode` as a chunked, tail-to-head segment chain, one signed `NewSegment` tx per
/// chunk. Segment keys are `[key_seed + i; 32]`; pick seeds with enough headroom to avoid
/// collisions. Returns segment `AccountId`s, first to last.
fn upload_program_segments(
    state: &mut V03State,
    bytecode: &[u8],
    key_seed: u8,
    block_id: BlockId,
) -> Vec<AccountId> {
    let chunks: Vec<&[u8]> = bytecode
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
        .collect();
    assert!(!chunks.is_empty(), "bytecode must not be empty");

    let segment_keys: Vec<PrivateKey> = (0..chunks.len())
        .map(|i| {
            let seed = key_seed
                .checked_add(u8::try_from(i).expect("chunk count fits in a u8"))
                .expect("key_seed left enough headroom for every chunk");
            PrivateKey::try_new([seed; 32]).unwrap()
        })
        .collect();
    let segment_ids: Vec<AccountId> = segment_keys
        .iter()
        .map(|key| AccountId::from(&PublicKey::new_from_private_key(key)))
        .collect();

    for (i, chunk) in chunks.iter().enumerate().rev() {
        let next_segment = segment_ids.get(i + 1).copied();
        submit_loader_instruction(
            state,
            &segment_keys[i],
            next_segment.into_iter().collect(),
            program_loader_core::Instruction::WriteSegment {
                bytecode: (*chunk).to_vec(),
                next_segment,
            },
            block_id,
        )
        .unwrap_or_else(|e| panic!("NewSegment {i} should succeed against an unclaimed target: {e:?}"));
    }

    segment_ids
}

/// Uploads `bytecode`'s segment chain (see [`upload_program_segments`]) then a header pointing
/// at it, signed by `header_key`. Returns the header's `AccountId`.
fn deploy_program(
    state: &mut V03State,
    bytecode: Vec<u8>,
    key_seed: u8,
    header_key: &PrivateKey,
    block_id: BlockId,
    immutable: bool,
) -> AccountId {
    let segment_ids = upload_program_segments(state, &bytecode, key_seed, block_id);
    let header_id = AccountId::from(&PublicKey::new_from_private_key(header_key));

    submit_loader_instruction(
        state,
        header_key,
        segment_ids.clone(),
        program_loader_core::Instruction::CreateHeader {
            first_segment: segment_ids[0],
            immutable,
        },
        block_id,
    )
    .expect("UploadHeader should succeed against an unclaimed target");

    header_id
}

/// Submits a `program_loader` instruction as a public transaction targeting the `AccountId`
/// `key` bijects to, with `extra_accounts` appended read-only after that target.
fn submit_loader_instruction(
    state: &mut V03State,
    key: &PrivateKey,
    extra_accounts: Vec<AccountId>,
    instruction: program_loader_core::Instruction,
    block_id: BlockId,
) -> Result<(), lee::error::LeeError> {
    let target = AccountId::from(&PublicKey::new_from_private_key(key));
    let nonce = state.get_account_by_id(target).nonce;
    let mut account_ids = vec![target];
    account_ids.extend(extra_accounts);
    let message = lee::public_transaction::Message::try_new(
        PROGRAM_LOADER_ACCOUNT_ID,
        account_ids,
        vec![nonce],
        instruction,
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[key]);
    let tx = PublicTransaction::new(message, witness_set);
    state.transition_from_public_transaction(&tx, block_id, 0)
}

#[test]
fn loader_deploys_program() {
    let mut state = V03State::new();
    let header_key = PrivateKey::try_new([39; 32]).unwrap();

    let bytecode = test_programs::claimer().elf().to_vec();
    let image_id: ProgramId = risc0_binfmt::compute_image_id(&bytecode).unwrap().into();
    let chunk_count = bytecode
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
        .count();

    let header = deploy_program(&mut state, bytecode.clone(), 20, &header_key, 1, true);

    let deployed_header = state.get_account_by_id(header);
    assert_eq!(deployed_header.program_owner, PROGRAM_LOADER_ACCOUNT_ID);
    let header_data = program_loader_core::ProgramHeader::try_from(&deployed_header.data)
        .expect("deployed header account data should decode as ProgramHeader");
    assert_eq!(header_data.image_id, image_id);
    assert!(header_data.immutable);

    let first_segment = state.get_account_by_id(header_data.program_first_segment);
    assert_eq!(first_segment.program_owner, PROGRAM_LOADER_ACCOUNT_ID);
    let first_segment_data = program_loader_core::ProgramSegment::try_from(&first_segment.data)
        .expect("deployed segment account data should decode as ProgramSegment");
    assert_eq!(
        first_segment_data.bytecode,
        bytecode[..program_loader_core::MAX_SEGMENT_DATA_LEN.min(bytecode.len())]
    );
    assert_eq!(first_segment_data.next_segment.is_some(), chunk_count > 1);
}

/// `get_program` must find a deployed program directly: decode the header, reconstruct the
/// bytecode by walking its segment chain, and return it exactly as deployed.
#[test]
fn loader_deployed_program_is_found_by_get_program() {
    let mut state = V03State::new();
    let header_key = PrivateKey::try_new([59; 32]).unwrap();

    let bytecode = test_programs::claimer().elf().to_vec();
    let image_id: ProgramId = risc0_binfmt::compute_image_id(&bytecode).unwrap().into();

    let header = deploy_program(&mut state, bytecode.clone(), 40, &header_key, 1, true);

    let (found_image_id, found_bytecode) = state
        .get_program(header)
        .expect("a freshly-deployed program must reconstruct without error")
        .expect("a freshly-deployed program must be found");
    assert_eq!(found_image_id, image_id);
    assert_eq!(found_bytecode, bytecode);
}

#[test]
fn get_program_returns_none_for_an_undeployed_account() {
    let state = V03State::new();
    assert_eq!(state.get_program(AccountId::new([42; 32])).unwrap(), None);
}

/// A deployed program must be a fully ordinary dispatch target afterward: `get_program` has to
/// find it by decoding the header and walking its segment chain, and dispatch has to actually
/// execute it.
#[test]
fn loader_deployed_program_is_invocable_via_dispatch() {
    let mut state = V03State::new();
    let header_key = PrivateKey::try_new([79; 32]).unwrap();

    let bytecode = test_programs::claimer().elf().to_vec();
    let header = deploy_program(&mut state, bytecode, 60, &header_key, 1, true);

    // `claimer` claims its one pre_state account with `Claim::Authorized`, which requires the
    // account to be signed for and to start out default-owned.
    let key = PrivateKey::try_new([7; 32]).unwrap();
    let account_id = AccountId::from(&PublicKey::new_from_private_key(&key));
    state.force_insert_account(account_id, Account::default());

    let message =
        lee::public_transaction::Message::try_new(header, vec![account_id], vec![Nonce(0)], ())
            .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&key]);
    let invoke_tx = PublicTransaction::new(message, witness_set);

    state
        .transition_from_public_transaction(&invoke_tx, 2, 0)
        .expect("a deployed program must be dispatchable and executable");

    assert_eq!(state.get_account_by_id(account_id).program_owner, header);
}

#[test]
fn loader_rejects_new_segment_against_an_already_claimed_target() {
    let mut state = V03State::new();
    let segment_key = PrivateKey::try_new([207; 32]).unwrap();

    let bytecode = vec![7_u8; 1024];
    submit_loader_instruction(
        &mut state,
        &segment_key,
        vec![],
        program_loader_core::Instruction::WriteSegment {
            bytecode: bytecode.clone(),
            next_segment: None,
        },
        1,
    )
    .expect("first NewSegment should succeed");

    let result = submit_loader_instruction(
        &mut state,
        &segment_key,
        vec![],
        program_loader_core::Instruction::WriteSegment {
            bytecode,
            next_segment: None,
        },
        2,
    );

    assert!(
        result.is_err(),
        "writing a segment to an already-claimed account should fail, but got: {result:?}"
    );
}

/// `image_id` is only ever recomputed when a header is written, so invalid bytecode is accepted
/// by `NewSegment` (segments are opaque bytes) and only rejected once `UploadHeader` tries to
/// hash the reconstructed chain.
#[test]
fn loader_rejects_invalid_bytecode() {
    let mut state = V03State::new();
    let segment_key = PrivateKey::try_new([208; 32]).unwrap();
    let header_key = PrivateKey::try_new([209; 32]).unwrap();
    let segment_id = AccountId::from(&PublicKey::new_from_private_key(&segment_key));

    let bytecode = b"this is not a valid RISC0 program binary".to_vec();
    submit_loader_instruction(
        &mut state,
        &segment_key,
        vec![],
        program_loader_core::Instruction::WriteSegment {
            bytecode,
            next_segment: None,
        },
        1,
    )
    .expect("NewSegment doesn't validate bytecode, so this should succeed");

    let result = submit_loader_instruction(
        &mut state,
        &header_key,
        vec![segment_id],
        program_loader_core::Instruction::CreateHeader {
            first_segment: segment_id,
            immutable: true,
        },
        2,
    );

    assert!(
        result.is_err(),
        "UploadHeader over invalid bytecode should fail, but got: {result:?}"
    );
}

#[test]
fn loader_rejects_claim_without_authorization() {
    let mut state = V03State::new();
    // Not signed for below — nothing authorizes this specific target account.
    let unsigned_target = AccountId::new([210; 32]);
    let signer_key = PrivateKey::try_new([211; 32]).unwrap();

    let message = lee::public_transaction::Message::try_new(
        PROGRAM_LOADER_ACCOUNT_ID,
        vec![unsigned_target],
        vec![Nonce(0)],
        program_loader_core::Instruction::WriteSegment {
            bytecode: vec![7_u8; 1024],
            next_segment: None,
        },
    )
    .unwrap();
    // Signs the message, but the signing key doesn't correspond to `unsigned_target`.
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&signer_key]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(
        result.is_err(),
        "claiming an account nobody signed for should fail, but got: {result:?}"
    );
}

#[test]
fn loader_rejects_upload_header_with_wrong_number_of_segment_accounts() {
    let mut state = V03State::new();
    let segment_key = PrivateKey::try_new([212; 32]).unwrap();
    let header_key = PrivateKey::try_new([213; 32]).unwrap();
    let segment_id = AccountId::from(&PublicKey::new_from_private_key(&segment_key));

    submit_loader_instruction(
        &mut state,
        &segment_key,
        vec![],
        program_loader_core::Instruction::WriteSegment {
            bytecode: vec![7_u8; 1024],
            next_segment: None,
        },
        1,
    )
    .expect("NewSegment should succeed");

    // The chain is one segment long, but an extra unrelated account is supplied alongside it.
    let extra = AccountId::new([214; 32]);
    let result = submit_loader_instruction(
        &mut state,
        &header_key,
        vec![segment_id, extra],
        program_loader_core::Instruction::CreateHeader {
            first_segment: segment_id,
            immutable: true,
        },
        2,
    );

    assert!(
        result.is_err(),
        "UploadHeader with more accounts than the real chain length should fail, but got: {result:?}"
    );
}

#[test]
fn loader_update_header_repoints_to_a_new_segment_chain() {
    let mut state = V03State::new();
    let header_key = PrivateKey::try_new([119; 32]).unwrap();

    let header = deploy_program(
        &mut state,
        test_programs::claimer().elf().to_vec(),
        100,
        &header_key,
        1,
        false,
    );
    let original_image_id = state.get_program_image_id(header).unwrap();

    let new_bytecode = test_programs::chain_caller().elf().to_vec();
    let new_image_id: ProgramId = risc0_binfmt::compute_image_id(&new_bytecode).unwrap().into();
    let new_segment_ids = upload_program_segments(&mut state, &new_bytecode, 120, 2);

    // The same key that created the header re-authorizes rewriting it — no separate update key,
    // ordinary account authorization is what governs this.
    submit_loader_instruction(
        &mut state,
        &header_key,
        new_segment_ids.clone(),
        program_loader_core::Instruction::UpdateHeader {
            first_segment: new_segment_ids[0],
            immutable: true,
        },
        3,
    )
    .expect("UpdateHeader should succeed when signed by the header's own key");

    let (found_image_id, found_bytecode) = state
        .get_program(header)
        .expect("updated program must reconstruct without error")
        .expect("updated program must still be found at the same header address");
    assert_eq!(found_image_id, new_image_id);
    assert_ne!(found_image_id, original_image_id);
    assert_eq!(found_bytecode, new_bytecode);
}

#[test]
fn loader_rejects_update_header_when_immutable() {
    let mut state = V03State::new();
    let header_key = PrivateKey::try_new([179; 32]).unwrap();

    let header = deploy_program(
        &mut state,
        test_programs::claimer().elf().to_vec(),
        180,
        &header_key,
        1,
        true,
    );
    let original_image_id = state.get_program_image_id(header).unwrap();

    let new_segment_ids =
        upload_program_segments(&mut state, &test_programs::chain_caller().elf().to_vec(), 220, 2);

    let result = submit_loader_instruction(
        &mut state,
        &header_key,
        new_segment_ids.clone(),
        program_loader_core::Instruction::UpdateHeader {
            first_segment: new_segment_ids[0],
            immutable: true,
        },
        3,
    );

    assert!(
        result.is_err(),
        "UpdateHeader on an immutable header should fail even when signed by the header's own \
         key, but got: {result:?}"
    );
    assert_eq!(
        state.get_program_image_id(header).unwrap(),
        original_image_id,
        "a rejected UpdateHeader must leave the header untouched"
    );
}

#[test]
fn loader_rejects_update_header_without_authorization() {
    let mut state = V03State::new();
    let header_key = PrivateKey::try_new([149; 32]).unwrap();

    let header = deploy_program(
        &mut state,
        test_programs::claimer().elf().to_vec(),
        130,
        &header_key,
        1,
        false,
    );

    let new_segment_ids =
        upload_program_segments(&mut state, &test_programs::chain_caller().elf().to_vec(), 150, 2);
    let new_first_segment = new_segment_ids[0];

    // Signed by a key with no relationship to `header` at all — not even the original deployer's.
    let attacker_key = PrivateKey::try_new([227; 32]).unwrap();
    let message = lee::public_transaction::Message::try_new(
        PROGRAM_LOADER_ACCOUNT_ID,
        [vec![header], new_segment_ids].concat(),
        vec![Nonce(0)],
        program_loader_core::Instruction::UpdateHeader {
            first_segment: new_first_segment,
            immutable: true,
        },
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&attacker_key]);
    let tx = PublicTransaction::new(message, witness_set);
    let result = state.transition_from_public_transaction(&tx, 3, 0);

    assert!(
        result.is_err(),
        "UpdateHeader signed by an unrelated key should fail, but got: {result:?}"
    );
}

#[test]
#[ignore = "known limitation, not an addressing problem: a program that wants to chain-call \
            program_loader must carry the target bytecode through its own instruction_data to \
            build the ChainedCall, which costs ~1,400-1,500 cycles/byte of real guest \
            interpretation and blows the 32M-cycle public-execution cap for any \
            realistically-sized program. Making an arbitrary program able to decide mid-flow to \
            deploy something new, as one step among others it orchestrates, needs a mechanism \
            where the bytecode reaches program_loader without being copied through any \
            intermediary guest's interpreted execution (e.g. a commitment carried in \
            instruction_data with the real payload resolved out-of-band by the dispatcher) — \
            deferred to a future PR. The supported pattern today is program_loader as the \
            top-level entry point (see loader_deploys_program)."]
fn loader_deploys_program_via_chained_call() {
    let loader_id: ProgramId = PROGRAM_LOADER_ACCOUNT_ID.into();
    let forwarder = test_programs::chained_call_forwarder();
    let mut state = V03State::new().with_programs([forwarder.clone()]);

    let segment_key = PrivateKey::try_new([215; 32]).unwrap();
    let segment_id = AccountId::from(&PublicKey::new_from_private_key(&segment_key));
    let bytecode = test_programs::claimer().elf().to_vec();

    let inner_instruction_data = lee::program::Program::serialize_instruction(
        program_loader_core::Instruction::WriteSegment {
            bytecode,
            next_segment: None,
        },
    )
    .unwrap();

    let message = lee::public_transaction::Message::try_new(
        forwarder.deployed_account_id(),
        vec![segment_id],
        vec![],
        (loader_id, inner_instruction_data),
    )
    .unwrap();
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    state
        .transition_from_public_transaction(&tx, 1, 0)
        .expect("NewSegment via chained call should succeed");

    let deployed_segment = state.get_account_by_id(segment_id);
    assert_eq!(deployed_segment.program_owner, PROGRAM_LOADER_ACCOUNT_ID);
}
