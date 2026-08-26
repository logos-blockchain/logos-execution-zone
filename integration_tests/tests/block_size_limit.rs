#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::Result;
use bytesize::ByteSize;
use common::transaction::LeeTransaction;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, config::SequencerPartialConfig, deploy_targets,
    deploy_transaction, encoded_tx_size,
};
use lee::program::Program;
use lee_core::program::DEPLOYMENT_PROGRAM_ACCOUNT_ID;
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use tokio::test;

#[test]
async fn reject_oversized_transaction() -> Result<()> {
    let bytecode = test_programs::claimer().elf().to_vec();
    let (header, segment) = deploy_targets(&bytecode);
    let tx = LeeTransaction::Public(deploy_transaction(header, segment, bytecode));
    let tx_size = encoded_tx_size(&tx);

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_sequencer_partial_config(SequencerPartialConfig {
                    max_num_tx_in_block: 100,
                    max_block_size: ByteSize::b(tx_size),
                    mempool_max_size: 1000,
                    block_create_timeout: Duration::from_secs(10),
                    priority_fee: sequencer_core::config::default_priority_fee(),
                }),
        )
        .build()
        .await?;

    // Try to submit the transaction and expect an error
    let result = ctx.sequencer_client().send_transaction(tx).await;

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
    // A real Deploy of a valid guest binary: the native Deploy dispatch path parses
    // the bytecode as an actual RISC0 image, so an arbitrary small buffer no longer
    // qualifies as "a small transaction" the way it did under the legacy path.
    let bytecode = test_programs::claimer().elf().to_vec();
    let (header, segment) = deploy_targets(&bytecode);
    let tx = LeeTransaction::Public(deploy_transaction(header, segment, bytecode));
    let tx_size = encoded_tx_size(&tx);

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_sequencer_partial_config(SequencerPartialConfig {
                    max_num_tx_in_block: 100,
                    // TOFIX: should be `ByteSize::mib(1)` again once the program-as-account
                    // migration is finished.
                    max_block_size: ByteSize::b(tx_size + 10 * 1024),
                    mempool_max_size: 1000,
                    block_create_timeout: Duration::from_secs(10),
                    priority_fee: sequencer_core::config::default_priority_fee(),
                }),
        )
        .build()
        .await?;

    // This should succeed
    let result = ctx.sequencer_client().send_transaction(tx).await;

    assert!(
        result.is_ok(),
        "Expected successful submission of small transaction, got error: {:?}",
        result.as_ref().unwrap_err()
    );

    Ok(())
}

#[test]
async fn transaction_deferred_to_next_block_when_current_full() -> Result<()> {
    let claimer = test_programs::claimer();
    let chain_caller = test_programs::chain_caller();

    let (claimer_header, claimer_segment) = deploy_targets(claimer.elf());
    let claimer_tx = LeeTransaction::Public(deploy_transaction(
        claimer_header,
        claimer_segment,
        claimer.elf().to_vec(),
    ));

    let (chain_caller_header, chain_caller_segment) = deploy_targets(chain_caller.elf());
    let chain_caller_tx = LeeTransaction::Public(deploy_transaction(
        chain_caller_header,
        chain_caller_segment,
        chain_caller.elf().to_vec(),
    ));

    // Block size to fit only one of the two transactions, leaving some room for headers
    // (e.g., 10 KiB)
    let max_tx_size = encoded_tx_size(&claimer_tx).max(encoded_tx_size(&chain_caller_tx));
    let block_size = ByteSize::b(max_tx_size + 10 * 1024);

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_sequencer_partial_config(SequencerPartialConfig {
                    max_num_tx_in_block: 100,
                    max_block_size: block_size,
                    mempool_max_size: 1000,
                    block_create_timeout: Duration::from_secs(10),
                    priority_fee: sequencer_core::config::default_priority_fee(),
                }),
        )
        .build()
        .await?;

    let initial_block_height = ctx.sequencer_client().get_last_block_id().await?;

    // Submit both program deployments
    ctx.sequencer_client().send_transaction(claimer_tx).await?;
    ctx.sequencer_client()
        .send_transaction(chain_caller_tx)
        .await?;

    // Wait for first block
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let block1 = ctx
        .sequencer_client()
        .get_block(initial_block_height + 1)
        .await?
        .unwrap();

    // Check which program is deployed in a block, by picking out its `Deploy` transactions and
    // decoding the real `image_id` of each one's bytecode.
    let get_program_ids = |block: &common::block::Block| -> Vec<lee::ProgramId> {
        block
            .body
            .transactions
            .iter()
            .filter_map(|tx| {
                let LeeTransaction::Public(public_tx) = tx else {
                    return None;
                };
                if public_tx.message.program_account_id != DEPLOYMENT_PROGRAM_ACCOUNT_ID {
                    return None;
                }
                let program_loader_core::Instruction::Deploy { bytecode } =
                    borsh::from_slice::<program_loader_core::Instruction>(
                        &public_tx.message.instruction_data,
                    )
                    .ok()?;
                Program::new(bytecode.into()).ok().map(|p| p.id())
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
        block1_program_ids[0],
        claimer.id(),
        "Expected claimer program to be deployed in block 1"
    );

    // Wait for second block
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let block2 = ctx
        .sequencer_client()
        .get_block(initial_block_height + 2)
        .await?
        .unwrap();
    let block2_program_ids = get_program_ids(&block2);

    // The other program should be in block 2
    assert_eq!(
        block2_program_ids.len(),
        1,
        "Expected exactly one program deployment in block 2"
    );
    assert_eq!(
        block2_program_ids[0],
        chain_caller.id(),
        "Expected chain_caller program to be deployed in block 2"
    );

    Ok(())
}
