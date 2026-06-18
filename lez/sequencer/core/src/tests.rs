#![expect(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use std::{pin::pin, time::Duration};

use common::{
    HashType,
    block::HashableBlockData,
    test_utils::sequencer_sign_key_for_testing,
    transaction::{LeeTransaction, clock_invocation},
};
use key_protocol::key_management::KeyChain;
use lee::{
    Account, AccountId, Data, EphemeralPublicKey, PrivacyPreservingTransaction, PrivateKey,
    PublicKey, PublicTransaction, SharedSecretKey, V03State,
    error::LeeError,
    execute_and_prove,
    privacy_preserving_transaction::{Message, circuit::ProgramWithDependencies},
    program::Program,
};
use lee_core::{
    Commitment, EncryptedAccountData, InputAccountIdentity, Nullifier,
    account::{AccountWithMetadata, Nonce},
    program::PdaSeed,
};
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use mempool::MemPoolHandle;
use storage::sequencer::sequencer_cells::PendingDepositEventRecord;
use tempfile::tempdir;
use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};

use crate::{
    TransactionOrigin,
    block_store::SequencerStore,
    build_genesis_state,
    config::{BedrockConfig, SequencerConfig},
    mock::SequencerCoreWithMockClients,
};

#[derive(borsh::BorshSerialize)]
struct DepositMetadataForEncoding {
    recipient_id: lee::AccountId,
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
        },
        retry_pending_blocks_timeout: Duration::from_mins(4),
        genesis: vec![],
    }
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
    let (mut sequencer, mempool_handle) =
        SequencerCoreWithMockClients::start_from_config(config).await;

    let tx = common::test_utils::produce_dummy_empty_transaction();
    mempool_handle
        .push((TransactionOrigin::User, tx))
        .await
        .unwrap();

    sequencer.produce_new_block().await.unwrap();

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
        match risc0_zkvm::serde::from_slice(&public_tx.message.instruction_data) {
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

#[tokio::test]
async fn start_from_config() {
    let config = setup_sequencer_config();
    let (sequencer, _mempool_handle) =
        SequencerCoreWithMockClients::start_from_config(config.clone()).await;

    assert_eq!(sequencer.chain_height, 1);
    assert_eq!(sequencer.sequencer_config.max_num_tx_in_block, 10);

    let acc1_account_id = initial_public_user_accounts()[0].account_id;
    let acc2_account_id = initial_public_user_accounts()[1].account_id;

    let balance_acc_1 = sequencer.state.get_account_by_id(acc1_account_id).balance;
    let balance_acc_2 = sequencer.state.get_account_by_id(acc2_account_id).balance;

    assert_eq!(10000, balance_acc_1);
    assert_eq!(20000, balance_acc_2);
}

#[tokio::test]
async fn start_from_config_opens_existing_db_if_it_exists() {
    let config = setup_sequencer_config();
    let temp_dir = tempdir().unwrap();
    let mut config = config;
    config.home = temp_dir.path().to_path_buf();

    let signing_key = lee::PrivateKey::try_new(config.signing_key).unwrap();
    let (genesis_state, genesis_txs) = build_genesis_state(&config);
    let genesis_hashable_data = HashableBlockData {
        block_id: 1,
        transactions: genesis_txs,
        prev_block_hash: HashType([0; 32]),
        timestamp: 0,
    };
    let genesis_block = genesis_hashable_data.into_pending_block(&signing_key);

    SequencerStore::create_db_with_genesis(
        &config.home.join("rocksdb"),
        &genesis_block,
        &genesis_state,
        signing_key,
    )
    .unwrap();

    let (sequencer, _mempool_handle) =
        SequencerCoreWithMockClients::start_from_config(config).await;
    assert_eq!(sequencer.chain_height, 1);
    assert!(sequencer.store.latest_block_meta().is_ok());
}

#[should_panic(expected = "Failed to open database")]
#[tokio::test]
async fn start_from_config_panics_when_db_open_returns_non_not_found_error() {
    let mut config = setup_sequencer_config();
    let temp_dir = tempdir().unwrap();
    config.home = temp_dir.path().to_path_buf();

    let db_path = config.home.join("rocksdb");

    std::fs::create_dir_all(&config.home).unwrap();
    // Force RocksDB open to fail with an IO error by placing a file at DB path.
    std::fs::write(&db_path, b"not-a-directory").unwrap();

    let _ = SequencerCoreWithMockClients::start_from_config(config).await;
}

#[tokio::test]
async fn start_from_config_replays_unfulfilled_deposit_events_from_db() {
    let config = setup_sequencer_config();
    let deposit_op_id = [13_u8; 32];
    let expected_amount = 1_u64;
    let recipient_id = initial_public_user_accounts()[0].account_id;

    {
        let (_sequencer, _mempool_handle) =
            SequencerCoreWithMockClients::start_from_config(config.clone()).await;
    }

    let pending_event = PendingDepositEventRecord {
        deposit_op_id: HashType(deposit_op_id),
        source_tx_hash: HashType([7_u8; 32]),
        amount: expected_amount,
        metadata: borsh::to_vec(&DepositMetadataForEncoding { recipient_id }).unwrap(),
        submitted_in_block_id: None,
    };

    {
        let signing_key = lee::PrivateKey::try_new(config.signing_key).unwrap();
        let store = SequencerStore::open_db(&config.home.join("rocksdb"), signing_key).unwrap();

        let inserted = store
            .dbio()
            .add_pending_deposit_event(pending_event)
            .unwrap();
        assert!(inserted);
    }

    let (mut sequencer, _mempool_handle) =
        SequencerCoreWithMockClients::start_from_config(config).await;

    let (origin, tx) = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some((origin, tx)) = sequencer.mempool.pop() {
                return (origin, tx);
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("Timed out waiting for pending deposit event to be replayed into mempool");

    match origin {
        TransactionOrigin::Sequencer => {}
        TransactionOrigin::User => {
            panic!("Unexpected user transaction in empty mempool replay test")
        }
    }

    assert!(tx_is_bridge_deposit(&tx, deposit_op_id, expected_amount));

    let pending_events = sequencer.store.get_unfulfilled_deposit_events().unwrap();
    let replayed_event = pending_events
        .into_iter()
        .find(|event| event.deposit_op_id == HashType(deposit_op_id))
        .expect("Pending deposit event should remain in DB until included in a block");
    assert!(replayed_event.submitted_in_block_id.is_none());
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

    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1, 0, acc2, 10, &sign_key1,
    );
    let result = tx.transaction_stateless_check();

    assert!(result.is_ok());
}

#[tokio::test]
async fn transaction_pre_check_native_transfer_other_signature() {
    let (mut sequencer, _mempool_handle) = common_setup().await;

    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;

    let sign_key2 = create_signing_key_for_account2();

    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1, 0, acc2, 10, &sign_key2,
    );

    // Signature is valid, stateless check pass
    let tx = tx.transaction_stateless_check().unwrap();

    // Signature is not from sender. Execution fails
    let result = tx.execute_check_on_state(&mut sequencer.state, 0, 0);

    assert!(matches!(
        result,
        Err(lee::error::LeeError::ProgramExecutionFailed(_))
    ));
}

#[tokio::test]
async fn transaction_pre_check_native_transfer_sent_too_much() {
    let (mut sequencer, _mempool_handle) = common_setup().await;

    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;

    let sign_key1 = create_signing_key_for_account1();

    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1, 0, acc2, 10_000_000, &sign_key1,
    );

    let result = tx.transaction_stateless_check();

    // Passed pre-check
    assert!(result.is_ok());

    let result = result
        .unwrap()
        .execute_check_on_state(&mut sequencer.state, 0, 0);
    let is_failed_at_balance_mismatch = matches!(
        result.err().unwrap(),
        lee::error::LeeError::ProgramExecutionFailed(_)
    );

    assert!(is_failed_at_balance_mismatch);
}

#[tokio::test]
async fn transaction_execute_native_transfer() {
    let (mut sequencer, _mempool_handle) = common_setup().await;

    let acc1 = initial_public_user_accounts()[0].account_id;
    let acc2 = initial_public_user_accounts()[1].account_id;

    let sign_key1 = create_signing_key_for_account1();

    let tx = common::test_utils::create_transaction_native_token_transfer(
        acc1, 0, acc2, 100, &sign_key1,
    );

    tx.execute_check_on_state(&mut sequencer.state, 0, 0)
        .unwrap();

    let bal_from = sequencer.state.get_account_by_id(acc1).balance;
    let bal_to = sequencer.state.get_account_by_id(acc2).balance;

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
    sequencer.produce_new_block().await.unwrap();

    // Resolve the pending push
    assert!(push_fut.await.is_ok());
}

#[tokio::test]
async fn build_block_from_mempool() {
    let (mut sequencer, mempool_handle) = common_setup().await;
    let genesis_height = sequencer.chain_height;

    let tx = common::test_utils::produce_dummy_empty_transaction();
    mempool_handle
        .push((TransactionOrigin::User, tx))
        .await
        .unwrap();

    let result = sequencer.build_block_from_mempool();
    assert!(result.is_ok());
    assert_eq!(sequencer.chain_height, genesis_height + 1);
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
    sequencer.produce_new_block().await.unwrap();
    let block = sequencer
        .store
        .get_block_at_id(sequencer.chain_height)
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
    sequencer.produce_new_block().await.unwrap();
    let block = sequencer
        .store
        .get_block_at_id(sequencer.chain_height)
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
    sequencer.produce_new_block().await.unwrap();
    let block = sequencer
        .store
        .get_block_at_id(sequencer.chain_height)
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
    {
        let (mut sequencer, mempool_handle) =
            SequencerCoreWithMockClients::start_from_config(config.clone()).await;
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
        sequencer.produce_new_block().await.unwrap();
        let block = sequencer
            .store
            .get_block_at_id(sequencer.chain_height)
            .unwrap()
            .unwrap();
        assert_eq!(
            block.body.transactions,
            vec![
                tx.clone(),
                LeeTransaction::Public(clock_invocation(block.header.timestamp))
            ]
        );
    }

    // Instantiating a new sequencer from the same config. This should load the existing block
    // with the above transaction and update the state to reflect that.
    let (sequencer, _mempool_handle) =
        SequencerCoreWithMockClients::start_from_config(config.clone()).await;
    let balance_acc_1 = sequencer.state.get_account_by_id(acc1_account_id).balance;
    let balance_acc_2 = sequencer.state.get_account_by_id(acc2_account_id).balance;

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
    let (mut sequencer, _mempool_handle) =
        SequencerCoreWithMockClients::start_from_config(config).await;
    sequencer.produce_new_block().await.unwrap();
    sequencer.produce_new_block().await.unwrap();
    sequencer.produce_new_block().await.unwrap();
    assert_eq!(sequencer.get_pending_blocks().unwrap().len(), 4);
}

#[tokio::test]
async fn delete_blocks() {
    let config = setup_sequencer_config();
    let (mut sequencer, _mempool_handle) =
        SequencerCoreWithMockClients::start_from_config(config).await;
    sequencer.produce_new_block().await.unwrap();
    sequencer.produce_new_block().await.unwrap();
    sequencer.produce_new_block().await.unwrap();

    let last_finalized_block = 3;
    sequencer
        .clean_finalized_blocks_from_db(last_finalized_block)
        .unwrap();

    assert_eq!(sequencer.get_pending_blocks().unwrap().len(), 1);
}

#[tokio::test]
async fn produce_block_with_correct_prev_meta_after_restart() {
    let config = setup_sequencer_config();
    let acc1_account_id = initial_public_user_accounts()[0].account_id;
    let acc2_account_id = initial_public_user_accounts()[1].account_id;

    // Step 1: Create initial database with some block metadata
    let expected_prev_meta = {
        let (mut sequencer, mempool_handle) =
            SequencerCoreWithMockClients::start_from_config(config.clone()).await;

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
        sequencer.produce_new_block().await.unwrap();

        // Get the metadata of the last block produced
        sequencer.store.latest_block_meta().unwrap()
    };

    // Step 2: Restart sequencer from the same storage
    let (mut sequencer, mempool_handle) =
        SequencerCoreWithMockClients::start_from_config(config.clone()).await;

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
    sequencer.produce_new_block().await.unwrap();

    // Step 5: Verify the new block has correct previous block metadata
    let new_block = sequencer
        .store
        .get_block_at_id(sequencer.chain_height)
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
    sequencer.produce_new_block().await.unwrap();

    let block = sequencer
        .store
        .get_block_at_id(sequencer.chain_height)
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
    sequencer.produce_new_block().await.unwrap();

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
    sequencer.produce_new_block().await.unwrap();

    let block = sequencer
        .store
        .get_block_at_id(sequencer.chain_height)
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
    let mut corrupted = sequencer.state.get_account_by_id(clock_account_id);
    corrupted.data = vec![0xff; 3].try_into().unwrap();
    sequencer
        .state
        .force_insert_account(clock_account_id, corrupted);

    // Push a dummy transaction so the mempool is non-empty.
    let tx = common::test_utils::produce_dummy_empty_transaction();
    mempool_handle
        .push((TransactionOrigin::User, tx))
        .await
        .unwrap();

    // Block production must fail because the appended clock tx cannot execute.
    let result = sequencer.produce_new_block().await;
    assert!(
        result.is_err(),
        "Block production should abort when clock account data is corrupted"
    );
}

#[test]
fn private_bridge_withdraw_invocation_is_dropped() {
    let sender_keys = KeyChain::new_os_random();
    let sender_account_id =
        AccountId::for_regular_private_account(&sender_keys.nullifier_public_key, 0);
    let sender_private_account = Account {
        program_owner: programs::authenticated_transfer().id(),
        balance: 100,
        nonce: Nonce(0xdead_beef),
        data: Data::default(),
    };
    let bridge_account_id = system_accounts::bridge_account_id();

    let mut state = V03State::new()
        .with_public_accounts([(bridge_account_id, system_accounts::bridge_account())])
        .with_private_accounts([(
            Commitment::new(&sender_account_id, &sender_private_account),
            Nullifier::for_account_initialization(&sender_account_id),
        )]);

    let sender_commitment = Commitment::new(&sender_account_id, &sender_private_account);

    let sender_pre = AccountWithMetadata::new(
        sender_private_account,
        true,
        (&sender_keys.nullifier_public_key, 0),
    );
    let bridge_pre = AccountWithMetadata::new(
        state.get_account_by_id(bridge_account_id),
        false,
        bridge_account_id,
    );

    let shared_secret = SharedSecretKey::encapsulate(&sender_keys.viewing_public_key).0;

    let instruction = Program::serialize_instruction(bridge_core::Instruction::Withdraw {
        amount: 1,
        bedrock_account_pk: [0; 32],
    })
    .unwrap();

    let program_with_deps = ProgramWithDependencies::new(
        programs::bridge(),
        [(
            programs::authenticated_transfer().id(),
            programs::authenticated_transfer(),
        )]
        .into(),
    );

    let (output, proof) = execute_and_prove(
        vec![sender_pre, bridge_pre],
        instruction,
        vec![
            InputAccountIdentity::PrivateAuthorizedUpdate {
                epk: EphemeralPublicKey(vec![12_u8; 1088]),
                view_tag: EncryptedAccountData::compute_view_tag(
                    &sender_keys.nullifier_public_key,
                    &sender_keys.viewing_public_key,
                ),
                ssk: shared_secret,
                nsk: sender_keys.private_key_holder.nullifier_secret_key,
                membership_proof: state
                    .get_proof_for_commitment(&sender_commitment)
                    .expect("sender commitment must be in state"),
                identifier: 0,
            },
            InputAccountIdentity::Public,
        ],
        &program_with_deps,
    )
    .expect("Execution should succeed");

    let message = Message::try_from_circuit_output(vec![bridge_account_id], vec![], output)
        .expect("Message construction should succeed");
    let witness_set =
        lee::privacy_preserving_transaction::WitnessSet::for_message(&message, proof, &[]);
    let tx = LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(
        message,
        witness_set,
    ));
    let res = tx.execute_check_on_state(&mut state, 1, 0);

    assert!(
        matches!(res, Err(LeeError::InvalidInput(_))),
        "Bridge withdraw invocation should be rejected in private execution"
    );
}

/// Builds a [`V03State`] with the clock program and `program` registered, the three clock
/// accounts initialized, and the clock advanced to `clock_timestamp` so that reads of the
/// `CLOCK_01` account observe it.
fn state_with_clock_and_program(program: Program, clock_timestamp: u64) -> V03State {
    let mut state = V03State::new().with_programs([programs::clock(), program]);
    for clock_id in system_accounts::clock_account_ids() {
        state.force_insert_account(clock_id, system_accounts::clock_account());
    }
    state
        .transition_from_public_transaction(
            &clock_invocation(clock_timestamp),
            1,
            clock_timestamp,
        )
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
            program_owner: programs::authenticated_transfer().id(),
            ..Account::default()
        },
    );

    let key1 = PrivateKey::try_new([1; 32]).unwrap();
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&key1));
    state.force_insert_account(
        sender_id,
        Account {
            program_owner: test_programs::time_locked_transfer().id(),
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
            program_owner: programs::authenticated_transfer().id(),
            ..Account::default()
        },
    );

    let key1 = PrivateKey::try_new([1; 32]).unwrap();
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&key1));
    state.force_insert_account(
        sender_id,
        Account {
            program_owner: test_programs::time_locked_transfer().id(),
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
    let program_id = test_programs::pinata_cooldown().id();
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
    let mut state =
        state_with_clock_and_program(test_programs::pinata_cooldown(), block_timestamp);

    // The winner must be a non-default account so the program may credit it without claiming.
    state.force_insert_account(
        winner_id,
        Account {
            program_owner: programs::authenticated_transfer().id(),
            ..Account::default()
        },
    );
    state.force_insert_account(
        pinata_id,
        Account {
            program_owner: test_programs::pinata_cooldown().id(),
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
    let mut state =
        state_with_clock_and_program(test_programs::pinata_cooldown(), block_timestamp);

    state.force_insert_account(
        winner_id,
        Account {
            program_owner: programs::authenticated_transfer().id(),
            ..Account::default()
        },
    );
    state.force_insert_account(
        pinata_id,
        Account {
            program_owner: test_programs::pinata_cooldown().id(),
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
        AccountId::for_public_pda(&pinata_token.id(), &PdaSeed::new([0; 32]));
    let winner_token_holding_id = AccountId::new([3; 32]);

    let expected_winner_account_holding = token_core::TokenHolding::Fungible {
        definition_id: pinata_token_definition_id,
        balance: 150,
    };
    let expected_winner_token_holding_post = Account {
        program_owner: token.id(),
        data: Data::from(&expected_winner_account_holding),
        ..Account::default()
    };

    // Register the pinata-token and token programs and create the pinata definition account.
    // This replaces the removed `add_pinata_token_program` helper.
    let mut state = V03State::new().with_programs([pinata_token.clone(), token.clone()]);
    state.force_insert_account(
        pinata_definition_id,
        Account {
            program_owner: pinata_token.id(),
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
            program_owner: token.id(),
            data: Data::from(&token_definition),
            ..Account::default()
        },
    );
    state.force_insert_account(
        pinata_token_holding_id,
        Account {
            program_owner: token.id(),
            data: Data::from(&token_holding),
            ..Account::default()
        },
    );
    state.force_insert_account(
        winner_token_holding_id,
        Account {
            program_owner: token.id(),
            data: Data::from(&winner_holding),
            ..Account::default()
        },
    );

    // Submit a solution to the pinata program to claim the prize
    let solution: u128 = 989_106;
    let message = lee::public_transaction::Message::try_new(
        pinata_token.id(),
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
