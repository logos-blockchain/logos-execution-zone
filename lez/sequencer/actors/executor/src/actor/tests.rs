use std::{collections::BTreeMap, time::Duration};

use anyhow::Result;
use bytesize::ByteSize;
use common::{
    HashType,
    block::{BedrockStatus, Block, BlockBody, BlockHeader, BlockMeta},
    transaction::LeeTransaction,
};
use kameo::{actor::Spawn as _, error::SendError};
use lee::{
    Account, AccountId, PrivateKey, ProgramShardSelector, PublicKey, PublicTransaction, Signature,
    public_transaction::{Message, WitnessSet},
};
use lee_core::native_token::{Instruction as NativeInstruction, NATIVE_TOKEN_PROGRAM_ID};
use mockall::predicate::{always, eq, function};
use num_bigint::BigUint;
use sequencer_bedrock_actor::{
    mock::MockBedrockActor,
    protocol::{ChannelSeq, Checkpoint, HeaderId, PublishOutcome, Slot},
};
use sequencer_core::{
    MsgId,
    config::{BedrockConfig, SequencerConfig},
};
use sequencer_stake_core::{SequencerEntry, SequencerKey};
use sequencer_storage_actor::{mock::MockStorageActor, protocol::StoreUpdateOutcome};
use tempfile::TempDir;
use tokio::{sync::mpsc, test, time::timeout};

use crate::{
    ExecutorActor,
    actor::BlockedAttempts,
    protocol::{self, TransactionOrigin},
};

mod reconstruction;

fn sequencer_config() -> (SequencerConfig, TempDir) {
    let home = TempDir::new().expect("Failed to create temporary home directory");
    let config = SequencerConfig {
        home: home.path().to_path_buf(),
        max_num_tx_in_block: 10,
        max_block_size: ByteSize::kib(1024),
        mempool_max_size: 10,
        block_create_timeout: std::time::Duration::from_secs(5),
        retry_pending_blocks_timeout: std::time::Duration::from_secs(5),
        signing_key: Some([37; 32]),
        bedrock_config: BedrockConfig {
            channel_id: [0; 32].into(),
            node_url: "http://not-used".parse().expect("Failed to parse URL"),
            auth: None,
            funding_key: BigUint::default().into(),
            priority_fee_percent: sequencer_core::config::default_priority_fee_percent(),
            channel_params: sequencer_core::config::default_channel_params(),
        },
        genesis: Vec::new(),
        cross_zone: None,
        metrics_address: None,
        gossip: None,
    };

    (config, home)
}

fn test_transaction() -> LeeTransaction {
    let key2 = PrivateKey::new_os_random();
    let acc2 = AccountId::from(&PublicKey::new_from_private_key(&key2));

    // Fees are self-pay: the payer must be a funded initial-state account that
    // signs the transaction in the ordinary witness set, so it leads the
    // account list and signs alongside the other party.
    let accounts = testnet_initial_state::initial_pub_accounts_private_keys();
    let payer = accounts[0].account_id;
    let payer_key = accounts[0].pub_sign_key.clone();

    let nonces = vec![0_u128.into(), 0_u128.into()];
    let message = Message::try_new_with_fees(
        NATIVE_TOKEN_PROGRAM_ID,
        vec![
            ProgramShardSelector::balance(payer),
            ProgramShardSelector::balance(acc2),
        ],
        nonces,
        NativeInstruction::Transfer { amount: 1337 },
        common::test_utils::test_fee_declaration(payer),
    )
    .unwrap();

    let witness_set = WitnessSet::for_message(&message, &[&payer_key, &key2]);
    PublicTransaction::new(message, witness_set).into()
}

/// A Bedrock whose channel exists but holds nothing yet, with this node on turn.
fn prepare_mock_bedrock_with_empty_channel() -> MockBedrockActor {
    let mut mock_bedrock = MockBedrockActor::default();
    mock_bedrock
        .expect_handle_check_channel_exists()
        .returning(|_msg, _ctx| Ok(true));
    mock_bedrock
        .expect_handle_get_channel_tip_slot()
        .returning(|_msg, _ctx| Ok(Some(Slot::from(0))));
    mock_bedrock
        .expect_handle_read_channel()
        .returning(|_msg, _ctx| Ok(Box::pin(futures::stream::empty())));
    mock_bedrock
        .expect_handle_check_is_our_turn()
        .returning(|_msg, _ctx| true);
    mock_bedrock
}

/// A config whose home already holds a known Bedrock signing key, so the stake
/// config can name this node before the sequencer ever reads the key.
fn staked_sequencer_config() -> (SequencerConfig, TempDir, SequencerKey) {
    const BEDROCK_KEY: [u8; 32] = [0x5e; 32];

    let (config, home) = sequencer_config();
    std::fs::write(config.home.join("bedrock_signing_key"), BEDROCK_KEY)
        .expect("Failed to seed the Bedrock signing key");
    let sequencer_key = SequencerKey::new(
        sequencer_core::load_or_create_signing_key(&config.home.join("bedrock_signing_key"))
            .expect("the seeded key loads")
            .public_key()
            .to_bytes(),
    )
    .expect("the seeded key is a valid Ed25519 public key");

    (config, home, sequencer_key)
}

/// The stake config naming `sequencer_key` as a staked sequencer, which block
/// production needs to find itself in before it will build anything.
fn stake_entries(sequencer_key: SequencerKey) -> BTreeMap<SequencerKey, SequencerEntry> {
    [(
        sequencer_key,
        SequencerEntry {
            account_id: testnet_initial_state::initial_public_user_accounts()[0].account_id,
            total_staked: 1,
            total_pending_unstake: 0,
        },
    )]
    .into()
}

fn prepare_mock_storage_with_empty_genesis() -> MockStorageActor {
    prepare_mock_storage_with_stake(BTreeMap::new())
}

fn prepare_mock_storage_with_stake(
    entries: BTreeMap<SequencerKey, SequencerEntry>,
) -> MockStorageActor {
    let genesis_block_meta = BlockMeta {
        id: 1,
        hash: HashType::default(),
    };
    let genesis_block = Block {
        header: BlockHeader {
            block_id: genesis_block_meta.id,
            prev_block_hash: HashType::default(),
            hash: genesis_block_meta.hash,
            timestamp: 0,
            producer: PublicKey::new_from_private_key(
                &PrivateKey::try_new([1_u8; 32]).expect("valid key"),
            ),
            signature: Signature { value: [0; 64] },
        },
        body: BlockBody {
            transactions: vec![],
        },
        bedrock_status: BedrockStatus::Pending,
    };
    // The real genesis state, so programs are loaded and a transaction can
    // actually settle; only the stake config is layered on, to name this node.
    let state = testnet_initial_state::initial_state(false).with_public_accounts([(
        system_accounts::sequencer_stake_config_account_id(),
        Account::default().with_shard(
            programs::sequencer_stake_account_id(),
            sequencer_stake_core::SequencerStakeConfig {
                channel_params: Some(sequencer_stake_core::ChannelParams {
                    minimum_sequencer_stake: 0,
                    posting_timeframe: system_accounts::DEFAULT_SEQUENCER_POSTING_TIMEFRAME,
                    posting_timeout: system_accounts::DEFAULT_SEQUENCER_POSTING_TIMEOUT,
                }),
                channel_id: Some([0xC1; 32]),
                entries,
            }
            .to_bytes()
            .try_into()
            .expect("Sequencer stake config must fit into ShardData"),
        ),
    )]);

    let mut mock_storage = MockStorageActor::new();

    mock_storage
        .expect_handle_get_first_block_id()
        .returning(|_, _| Ok(Some(1)));

    mock_storage
        .expect_handle_get_last_block_id()
        .returning(|_, _| Ok(Some(1)));

    let genesis_block_clone = genesis_block.clone();
    mock_storage
        .expect_handle_get_block()
        .with(
            eq(sequencer_storage_actor::protocol::GetBlock { block_id: 1 }),
            always(),
        )
        .returning(move |_, _| Ok(Some(genesis_block_clone.clone())));

    let state_clone = state.clone();
    mock_storage
        .expect_handle_get_lee_state()
        .returning(move |_, _| Ok(Some(state_clone.clone())));

    let genesis_block_meta_clone = genesis_block_meta.clone();
    mock_storage
        .expect_handle_get_final_snapshot()
        .returning(move |_, _| Ok(Some((state.clone(), genesis_block_meta_clone.clone()))));

    mock_storage
        .expect_handle_get_all_blocks()
        .returning(move |_, _| Ok(vec![genesis_block.clone()]));

    mock_storage
        .expect_handle_get_zone_checkpoint()
        .returning(|_, _| Ok(None));

    mock_storage
        .expect_handle_get_zone_anchor()
        .returning(|_, _| Ok(None));

    mock_storage
        .expect_handle_get_channel_cursor()
        .returning(|_, _| Ok(None));

    mock_storage
        .expect_handle_get_slash_record_bytes()
        .returning(|_, _| Ok(None));

    mock_storage
        .expect_handle_get_latest_block_meta()
        .returning(move |_, _| Ok(Some(genesis_block_meta.clone())));

    mock_storage
        .expect_handle_raise_published_high_water()
        .returning(|_, _| Ok(()));

    mock_storage
        .expect_handle_get_dead_letter_dispatches()
        .returning(|_, _| Ok(vec![]));

    mock_storage
}

/// A publish refused because the channel moved under the block costs nothing
/// but the turn: the transactions go back to the mempool, and the next turn
/// builds a fresh block from them against the state the updates left behind.
/// The refusal is an ordinary outcome, so it must not count as a production
/// failure either.
#[test]
async fn a_publish_refused_as_stale_returns_its_transactions_to_the_mempool() -> Result<()> {
    let _res = env_logger::try_init();

    let (config, _home, sequencer_key) = staked_sequencer_config();
    let mut mock_storage = prepare_mock_storage_with_stake(stake_entries(sequencer_key));
    // Startup published genesis, so the turn is not a rewind.
    mock_storage
        .expect_handle_get_published_high_water()
        .returning(|_msg, _ctx| Ok(Some(1)));
    mock_storage
        .expect_handle_get_pending_cross_zone_dispatches()
        .returning(|_msg, _ctx| Ok(Vec::new()));
    mock_storage
        .expect_handle_get_pending_deposit_events()
        .returning(|_msg, _ctx| Ok(Vec::new()));
    mock_storage
        .expect_handle_apply_store_update()
        .returning(|_msg, _ctx| Ok(StoreUpdateOutcome::default()));

    let mut mock_bedrock = prepare_mock_bedrock_with_empty_channel();
    mock_bedrock
        .expect_handle_get_accredited_keys()
        .returning(|_msg, _ctx| Ok(None));
    mock_bedrock
        .expect_handle_get_channel_tip_message_id()
        .returning(|_msg, _ctx| Ok(None));

    // The first publish loses the race; the second is served and its block
    // recorded, so the test can see what the retry carried.
    let (published_tx, mut published_rx) = mpsc::unbounded_channel();
    let refused_first = std::sync::atomic::AtomicBool::new(false);
    mock_bedrock
        .expect_handle_publish_block()
        .returning(move |msg, _ctx| {
            if !refused_first.swap(true, std::sync::atomic::Ordering::Relaxed) {
                return Err(sequencer_bedrock_actor::error::Error::ChannelMoved {
                    provided: msg.expected_seq.unwrap_or(ChannelSeq::mocked(0)),
                    current: ChannelSeq::mocked(7),
                });
            }
            let msg_id = MsgId::from(msg.block.header.hash.0);
            published_tx
                .send(msg.block)
                .expect("the test still listens");
            Ok(PublishOutcome {
                this_msg: msg_id,
                checkpoint: Checkpoint {
                    last_msg_id: msg_id,
                    pending_txs: Vec::new(),
                    lib: HeaderId::from([0; 32]),
                    lib_slot: Slot::from(0),
                    channel_notes: Vec::new(),
                    finalized_config: MsgId::root(),
                },
                seq: ChannelSeq::mocked(8),
                released_notes: Vec::new(),
            })
        });

    let executor = ExecutorActor::spawn(
        ExecutorActor::new(
            config,
            MockStorageActor::spawn(mock_storage),
            MockBedrockActor::spawn(mock_bedrock),
        )
        .await?,
    );

    let transaction = test_transaction();
    let transaction_hash = transaction.hash();
    executor
        .ask(protocol::Transaction {
            transaction,
            origin: TransactionOrigin::User,
        })
        .await
        .expect("the mempool takes the transaction");

    // The refused turn inscribes nothing and leaves the actor healthy.
    executor
        .ask(protocol::ProduceBlock)
        .await
        .expect("a refused turn must still reply Ok");
    assert!(
        executor.is_alive(),
        "a refused publish is not a reason to stop producing"
    );
    assert!(
        published_rx.try_recv().is_err(),
        "nothing reached L1 on the refused turn"
    );

    // The next turn rebuilds from the requeued transaction and lands it.
    executor
        .ask(protocol::ProduceBlock)
        .await
        .expect("the retried turn must reply Ok");
    let published = published_rx
        .try_recv()
        .expect("the retried turn publishes a block");
    assert!(
        published
            .body
            .transactions
            .iter()
            .any(|tx| tx.hash() == transaction_hash),
        "the refused turn's transaction has to come back on the next one"
    );

    Ok(())
}

/// A moving tip is catch-up, not a wedge, so the run restarts on a new tip.
#[test]
async fn a_blocked_run_restarts_whenever_the_channel_tip_changes() {
    let mut blocked = BlockedAttempts::default();
    let first = MsgId::from([1_u8; 32]);
    let second = MsgId::from([2_u8; 32]);

    assert_eq!(blocked.record(first), 1);
    assert_eq!(blocked.record(first), 2);
    assert_eq!(
        blocked.record(second),
        1,
        "a different tip is a channel that moved, not a stuck one"
    );
    assert_eq!(blocked.record(second), 2);
}

/// A recovered node must not leave the gauge high.
#[test]
async fn clearing_a_blocked_run_reports_only_a_real_change() {
    let mut blocked = BlockedAttempts::default();
    assert!(!blocked.clear(), "nothing to clear before any skip");

    blocked.record(MsgId::from([1_u8; 32]));
    assert!(blocked.clear(), "a run that existed is worth reporting");
    assert!(!blocked.clear(), "and only once");

    assert_eq!(
        blocked.record(MsgId::from([1_u8; 32])),
        1,
        "a cleared run starts over"
    );
}

/// The scheduler's interval task gives up for good the first time it finds
/// this actor stopped, so a failed turn must not surface as an error — that
/// would end block production permanently.
#[test]
async fn a_failed_production_turn_does_not_stop_the_actor() -> Result<()> {
    let _res = env_logger::try_init();

    let (config, _home) = sequencer_config();
    let mut mock_storage = prepare_mock_storage_with_empty_genesis();
    // Startup published genesis, so the turn is not a rewind.
    mock_storage
        .expect_handle_get_published_high_water()
        .returning(|_msg, _ctx| Ok(Some(1)));
    mock_storage
        .expect_handle_get_pending_cross_zone_dispatches()
        .returning(|_msg, _ctx| Ok(Vec::new()));
    mock_storage
        .expect_handle_get_pending_deposit_events()
        .returning(|_msg, _ctx| Ok(Vec::new()));
    let storage_ref = MockStorageActor::spawn(mock_storage);
    let mut mock_bedrock = prepare_mock_bedrock_with_empty_channel();
    mock_bedrock
        .expect_handle_get_accredited_keys()
        .returning(|_msg, _ctx| Ok(None));

    let executor = ExecutorActor::spawn(
        ExecutorActor::new(
            config,
            storage_ref.clone(),
            MockBedrockActor::spawn(mock_bedrock),
        )
        .await?,
    );

    // Our key holds no stake entry, so production aborts.
    executor
        .ask(protocol::ProduceBlock)
        .await
        .expect("a failed turn must still reply Ok");
    assert!(executor.is_alive(), "the actor must survive a failed turn");

    // The store served the whole turn, so the failure was production's own.
    storage_ref
        .ask(sequencer_storage_actor::mock::Checkpoint)
        .await?;

    Ok(())
}

#[test]
async fn handle_transaction_fails_on_full_mempool() -> Result<()> {
    let _res = env_logger::try_init();

    let (config, _home) = sequencer_config();
    let mempool_max_size = config.mempool_max_size;

    let mock_storage = prepare_mock_storage_with_empty_genesis();
    let storage_ref = MockStorageActor::spawn(mock_storage);

    let executor = ExecutorActor::spawn(
        ExecutorActor::new(
            config,
            storage_ref.clone(),
            MockBedrockActor::spawn(prepare_mock_bedrock_with_empty_channel()),
        )
        .await?,
    );

    storage_ref
        .tell(sequencer_storage_actor::mock::Checkpoint)
        .await?;

    // Fill mempool
    for _ in 0..mempool_max_size {
        let tx = test_transaction();
        executor
            .ask(protocol::Transaction {
                transaction: tx,
                origin: TransactionOrigin::User,
            })
            .await?;
    }

    // Now the mempool is full, the next transaction should fail
    let tx = test_transaction();
    assert!(matches!(
        executor
            .ask(protocol::Transaction {
                transaction: tx,
                origin: TransactionOrigin::User
            })
            .await
            .map_err(SendError::err),
        Err(Some(crate::error::Error::MempoolIsFull))
    ));

    Ok(())
}

#[test]
async fn get_block_range_keeps_executor_responsive() -> Result<()> {
    /// Blocks the mock storage accepts but never answers.
    const STALLED_FIRST: u64 = 100;
    const STALLED_LAST: u64 = 105;

    let _res = env_logger::try_init();

    let (config, _home) = sequencer_config();

    let (stalled_tx, mut stalled_rx) = mpsc::unbounded_channel();
    #[expect(
        clippy::collection_is_never_read,
        reason = "Keeping the senders alive is what makes the asker wait forever"
    )]
    let mut held_replies = Vec::new();
    let mut mock_storage = prepare_mock_storage_with_empty_genesis();
    mock_storage
        .expect_handle_get_block()
        .with(
            function(|msg: &sequencer_storage_actor::protocol::GetBlock| {
                (STALLED_FIRST..=STALLED_LAST).contains(&msg.block_id)
            }),
            always(),
        )
        .returning(move |_, ctx| {
            // Holding the sender without ever sending leaves the asker waiting
            // forever, while storage itself keeps draining its mailbox.
            let (_delegated, reply_sender) = ctx.reply_sender();
            held_replies.extend(reply_sender);
            stalled_tx.send(()).expect("Test must still be listening");
            Ok(None)
        });

    let storage_ref = MockStorageActor::spawn(mock_storage);
    let executor = ExecutorActor::spawn(
        ExecutorActor::new(
            config,
            storage_ref.clone(),
            MockBedrockActor::spawn(prepare_mock_bedrock_with_empty_channel()),
        )
        .await?,
    );

    let range = (STALLED_FIRST..=STALLED_LAST)
        .try_into()
        .expect("Range must be within the allowed length");
    let stalled_request = tokio::spawn({
        let executor = executor.clone();
        async move { executor.ask(protocol::GetBlockRange { range }).await }
    });

    stalled_rx
        .recv()
        .await
        .expect("Executor must reach storage for the stalled range");

    timeout(
        Duration::from_secs(5),
        executor.ask(protocol::GetLastBlockId),
    )
    .await
    .expect("Executor must answer while the stalled range is still in flight")?;

    assert!(
        !stalled_request.is_finished(),
        "The stalled range must still be waiting, otherwise nothing was proven"
    );
    stalled_request.abort();

    storage_ref
        .tell(sequencer_storage_actor::mock::Checkpoint)
        .await?;

    Ok(())
}

#[test]
async fn handle_transaction_rejects_a_fee_invalid_submission() -> Result<()> {
    let _res = env_logger::try_init();

    let (config, _home) = sequencer_config();
    let mock_storage = prepare_mock_storage_with_empty_genesis();
    let storage_ref = MockStorageActor::spawn(mock_storage);
    let executor = ExecutorActor::spawn(
        ExecutorActor::new(
            config,
            storage_ref.clone(),
            MockBedrockActor::spawn(prepare_mock_bedrock_with_empty_channel()),
        )
        .await?,
    );
    storage_ref
        .tell(sequencer_storage_actor::mock::Checkpoint)
        .await?;

    // A charged transaction whose max_fee is 0 can never cover its reserve
    // (which prices at least the serialized bytes), so admission's static check
    // rejects it before it reaches the mempool. The fee is declared (so it
    // classifies as charged, not `MissingFeeDeclaration`) but set to 0.
    let key2 = PrivateKey::new_os_random();
    let acc2 = AccountId::from(&PublicKey::new_from_private_key(&key2));
    let accounts = testnet_initial_state::initial_pub_accounts_private_keys();
    let payer = accounts[0].account_id;
    let payer_key = accounts[0].pub_sign_key.clone();
    let message = Message::try_new_with_fees(
        NATIVE_TOKEN_PROGRAM_ID,
        vec![
            ProgramShardSelector::balance(payer),
            ProgramShardSelector::balance(acc2),
        ],
        vec![0_u128.into(), 0_u128.into()],
        NativeInstruction::Transfer { amount: 1337 },
        lee::FeeDeclaration::new(payer, 2_000_000, 0, 0),
    )
    .unwrap();
    let witness_set = WitnessSet::for_message(&message, &[&payer_key, &key2]);
    let tx: LeeTransaction = PublicTransaction::new(message, witness_set).into();

    let res = executor
        .ask(protocol::Transaction {
            transaction: tx,
            origin: TransactionOrigin::User,
        })
        .await;
    assert!(matches!(
        res.map_err(SendError::err),
        Err(Some(crate::error::Error::IncorrectFee(_)))
    ));

    Ok(())
}
