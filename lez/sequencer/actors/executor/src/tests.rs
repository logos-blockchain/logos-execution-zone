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
    Account, AccountId, PrivateKey, PublicKey, PublicTransaction, Signature, V03State,
    public_transaction::{Message, WitnessSet},
};
use mockall::predicate::{always, eq, function};
use num_bigint::BigUint;
use sequencer_core::{
    config::{BedrockConfig, SequencerConfig},
    mock::MockBlockPublisher,
};
use sequencer_storage_actor::mock::MockStorageActor;
use tempfile::TempDir;
use tokio::{sync::mpsc, test, time::timeout};

use crate::{ExecutorActor, protocol};

fn sequencer_config() -> (SequencerConfig, TempDir) {
    let home = TempDir::new().expect("Failed to create temporary home directory");
    let config = SequencerConfig {
        home: home.path().to_path_buf(),
        max_num_tx_in_block: 10,
        max_block_size: ByteSize::kib(1024),
        mempool_max_size: 10,
        block_create_timeout: std::time::Duration::from_secs(5),
        retry_pending_blocks_timeout: std::time::Duration::from_secs(5),
        signing_key: [37; 32],
        bedrock_config: BedrockConfig {
            channel_id: [0; 32].into(),
            node_url: "http://not-used".parse().expect("Failed to parse URL"),
            auth: None,
            funding_key: BigUint::default().into(),
            priority_fee: sequencer_core::config::default_priority_fee(),
        },
        genesis: Vec::new(),
        cross_zone: None,
        metrics_address: None,
        gossip: None,
    };

    (config, home)
}

fn test_transaction() -> LeeTransaction {
    let key1 = PrivateKey::new_os_random();
    let key2 = PrivateKey::new_os_random();
    let acc1 = AccountId::from(&PublicKey::new_from_private_key(&key1));
    let acc2 = AccountId::from(&PublicKey::new_from_private_key(&key2));

    let nonces = vec![0_u128.into(), 0_u128.into()];
    let instruction = 1337;
    let message = Message::try_new(
        test_programs::simple_balance_transfer().id(),
        vec![acc1, acc2],
        nonces,
        instruction,
    )
    .unwrap();

    let witness_set = WitnessSet::for_message(&message, &[&key1, &key2]);
    PublicTransaction::new(message, witness_set).into()
}

fn prepare_mock_storage_with_empty_genesis() -> MockStorageActor {
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
    let state = V03State::new().with_public_accounts([(
        system_accounts::sequencer_stake_config_account_id(),
        Account {
            data: sequencer_stake_core::SequencerStakeConfig {
                minimum_sequencer_stake: 0,
                entries: BTreeMap::new(),
            }
            .to_bytes()
            .try_into()
            .expect("Sequencer stake config must fit into Data"),
            ..Account::default()
        },
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
        .expect_handle_get_zone_checkpoint_bytes()
        .returning(|_, _| Ok(None));

    mock_storage
        .expect_handle_get_zone_anchor()
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

#[test]
async fn handle_transaction_fails_on_full_mempool() -> Result<()> {
    let _res = env_logger::try_init();

    let (config, _home) = sequencer_config();
    let mempool_max_size = config.mempool_max_size;

    let mock_storage = prepare_mock_storage_with_empty_genesis();
    let storage_ref = MockStorageActor::spawn(mock_storage);

    let executor = ExecutorActor::spawn(
        ExecutorActor::<MockBlockPublisher, _>::new(config, storage_ref.clone()).await,
    );

    storage_ref
        .tell(sequencer_storage_actor::mock::Checkpoint)
        .await?;

    // Fill mempool
    for _ in 0..mempool_max_size {
        let tx = test_transaction();
        executor
            .ask(protocol::Transaction { transaction: tx })
            .await?;
    }

    // Now the mempool is full, the next transaction should fail
    let tx = test_transaction();
    assert!(matches!(
        executor
            .ask(protocol::Transaction { transaction: tx })
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
        ExecutorActor::<MockBlockPublisher, _>::new(config, storage_ref.clone()).await,
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
