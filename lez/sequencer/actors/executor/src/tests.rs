use anyhow::Result;
use bytesize::ByteSize;
use common::transaction::LeeTransaction;
use kameo::{actor::Spawn as _, error::SendError};
use lee::{
    AccountId, PrivateKey, PublicKey, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use num_bigint::BigUint;
use sequencer_core::{
    config::{BedrockConfig, SequencerConfig},
    mock::MockBlockPublisher,
};
use tokio::test;

use crate::{ExecutorActor, protocol};

fn sequencer_config() -> (SequencerConfig, tempfile::TempDir) {
    let home = tempfile::tempdir().expect("Failed to create tmp home dir");

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
        test_programs::simple_balance_transfer().id().into(),
        vec![acc1, acc2],
        nonces,
        instruction,
    )
    .unwrap();

    let witness_set = WitnessSet::for_message(&message, &[&key1, &key2]);
    PublicTransaction::new(message, witness_set).into()
}

#[test]
async fn handle_transaction_fails_on_full_mempool() -> Result<()> {
    let _res = env_logger::try_init();

    let (config, _home) = sequencer_config();
    let mempool_max_size = config.mempool_max_size;
    let executor = ExecutorActor::spawn(ExecutorActor::<MockBlockPublisher>::new(config).await);

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
