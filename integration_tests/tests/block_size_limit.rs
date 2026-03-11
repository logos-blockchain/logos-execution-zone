#![expect(
    clippy::as_conversions,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::Result;
use bytesize::ByteSize;
use common::{block::HashableBlockData, transaction::NSSATransaction};
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, config::SequencerPartialConfig,
};
use nssa::program::Program;
use tokio::test;

#[test]
async fn reject_oversized_transaction() -> Result<()> {
    let ctx = TestContext::builder()
        .with_sequencer_partial_config(SequencerPartialConfig {
            max_num_tx_in_block: 100,
            max_block_size: ByteSize::mib(1),
            mempool_max_size: 1000,
            block_create_timeout: Duration::from_secs(10),
        })
        .build()
        .await?;

    // Create a transaction that's definitely too large
    // Block size is 1 MiB (1,048,576 bytes), minus ~200 bytes for header = ~1,048,376 bytes max tx
    // Create a 1.1 MiB binary to ensure it exceeds the limit
    let oversized_binary = vec![0_u8; 1100 * 1024]; // 1.1 MiB binary

    let message = nssa::program_deployment_transaction::Message::new(oversized_binary);
    let tx = nssa::ProgramDeploymentTransaction::new(message);

    // Try to submit the transaction and expect an error
    let result = ctx.sequencer_client().send_tx_program(tx).await;

    assert!(
        result.is_err(),
        "Expected error when submitting oversized transaction"
    );

    let err = result.unwrap_err();
    let err_str = format!("{err:?}");

    // Check if the error contains information about transaction being too large
    assert!(
        err_str.contains("TransactionTooLarge") || err_str.contains("too large"),
        "Expected TransactionTooLarge error, got: {err_str}"
    );

    Ok(())
}

#[test]
async fn accept_transaction_within_limit() -> Result<()> {
    let ctx = TestContext::builder()
        .with_sequencer_partial_config(SequencerPartialConfig {
            max_num_tx_in_block: 100,
            max_block_size: ByteSize::mib(1),
            mempool_max_size: 1000,
            block_create_timeout: Duration::from_secs(10),
        })
        .build()
        .await?;

    // Create a small program deployment that should fit
    let small_binary = vec![0_u8; 1024]; // 1 KiB binary

    let message = nssa::program_deployment_transaction::Message::new(small_binary);
    let tx = nssa::ProgramDeploymentTransaction::new(message);

    // This should succeed
    let result = ctx.sequencer_client().send_tx_program(tx).await;

    assert!(
        result.is_ok(),
        "Expected successful submission of small transaction, got error: {:?}",
        result.as_ref().unwrap_err()
    );

    Ok(())
}

#[test]
async fn transaction_deferred_to_next_block_when_current_full() -> Result<()> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let artifacts_dir =
        std::path::PathBuf::from(manifest_dir).join("../artifacts/test_program_methods");

    let burner_bytecode = std::fs::read(artifacts_dir.join("burner.bin"))?;
    let chain_caller_bytecode = std::fs::read(artifacts_dir.join("chain_caller.bin"))?;

    // Calculate block size to fit only one of the two transactions, leaving some room for headers
    // (e.g., 10 KiB)
    let max_program_size = burner_bytecode.len().max(chain_caller_bytecode.len());
    let block_size = ByteSize::b((max_program_size + 10 * 1024) as u64);

    let ctx = TestContext::builder()
        .with_sequencer_partial_config(SequencerPartialConfig {
            max_num_tx_in_block: 100,
            max_block_size: block_size,
            mempool_max_size: 1000,
            block_create_timeout: Duration::from_secs(10),
        })
        .build()
        .await?;

    let burner_id = Program::new(burner_bytecode.clone())?.id();
    let chain_caller_id = Program::new(chain_caller_bytecode.clone())?.id();

    let initial_block_height = ctx.sequencer_client().get_last_block().await?.last_block;

    // Submit both program deployments
    ctx.sequencer_client()
        .send_tx_program(nssa::ProgramDeploymentTransaction::new(
            nssa::program_deployment_transaction::Message::new(burner_bytecode),
        ))
        .await?;

    ctx.sequencer_client()
        .send_tx_program(nssa::ProgramDeploymentTransaction::new(
            nssa::program_deployment_transaction::Message::new(chain_caller_bytecode),
        ))
        .await?;

    // Wait for first block
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let block1_response = ctx
        .sequencer_client()
        .get_block(initial_block_height + 1)
        .await?;
    let block1: HashableBlockData = borsh::from_slice(&block1_response.block)?;

    // Check which program is in block 1
    let get_program_ids = |block: &HashableBlockData| -> Vec<nssa::ProgramId> {
        block
            .transactions
            .iter()
            .filter_map(|tx| {
                if let NSSATransaction::ProgramDeployment(deployment) = tx {
                    let bytecode = deployment.message.clone().into_bytecode();
                    Program::new(bytecode).ok().map(|p| p.id())
                } else {
                    None
                }
            })
            .collect()
    };

    let block1_program_ids = get_program_ids(&block1);

    // First program should be in block 1, but not both due to block size limit
    assert_eq!(
        block1_program_ids.len(),
        1,
        "Expected exactly one program deployment in block 1"
    );
    assert_eq!(
        block1_program_ids[0], burner_id,
        "Expected burner program to be deployed in block 1"
    );

    // Wait for second block
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let block2_response = ctx
        .sequencer_client()
        .get_block(initial_block_height + 2)
        .await?;
    let block2: HashableBlockData = borsh::from_slice(&block2_response.block)?;
    let block2_program_ids = get_program_ids(&block2);

    // The other program should be in block 2
    assert_eq!(
        block2_program_ids.len(),
        1,
        "Expected exactly one program deployment in block 2"
    );
    assert_eq!(
        block2_program_ids[0], chain_caller_id,
        "Expected chain_caller program to be deployed in block 2"
    );

    Ok(())
}
