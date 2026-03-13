use std::time::Duration;

use anyhow::Result;
use indexer_service_rpc::RpcClient;
use integration_tests::{TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, format_public_account_id};
use log::info;
use tokio::test;
use wallet::cli::{Command, programs::native_token_transfer::AuthTransferSubcommand};

/// Timeout in milliseconds to reliably await for block finalization
const L2_TO_L1_TIMEOUT_MILLIS: u64 = 600000;

#[test]
async fn indexer_test_run() -> Result<()> {
    let ctx = TestContext::new().await?;

    // RUN OBSERVATION
    tokio::time::sleep(std::time::Duration::from_millis(L2_TO_L1_TIMEOUT_MILLIS)).await;

    let last_block_seq = ctx
        .sequencer_client()
        .get_last_block()
        .await
        .unwrap()
        .last_block;

    info!("Last block on seq now is {last_block_seq}");

    let last_block_indexer = ctx
        .indexer_client()
        .get_last_finalized_block_id()
        .await
        .unwrap();

    info!("Last block on ind now is {last_block_indexer}");

    assert!(last_block_indexer > 1);

    Ok(())
}

#[test]
async fn indexer_block_batching() -> Result<()> {
    let ctx = TestContext::new().await?;

    // WAIT
    info!("Waiting for indexer to parse blocks");
    tokio::time::sleep(std::time::Duration::from_millis(L2_TO_L1_TIMEOUT_MILLIS)).await;

    let last_block_indexer = ctx
        .indexer_client()
        .get_last_finalized_block_id()
        .await
        .unwrap();

    info!("Last block on ind now is {last_block_indexer}");

    assert!(last_block_indexer > 1);

    // Getting wide batch to fit all blocks (from latest backwards)
    let mut block_batch = ctx.indexer_client().get_blocks(None, 100).await.unwrap();

    // Reverse to check chain consistency from oldest to newest
    block_batch.reverse();

    // Checking chain consistency
    let mut prev_block_hash = block_batch.first().unwrap().header.hash;

    for block in &block_batch[1..] {
        assert_eq!(block.header.prev_block_hash, prev_block_hash);

        info!("Block {} chain-consistent", block.header.block_id);

        prev_block_hash = block.header.hash;
    }

    Ok(())
}

#[test]
async fn indexer_state_consistency() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: format_public_account_id(ctx.existing_public_accounts()[0]),
        to: Some(format_public_account_id(ctx.existing_public_accounts()[1])),
        to_npk: None,
        to_vpk: None,
        amount: 100,
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move");
    let acc_1_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[0])
        .await?;
    let acc_2_balance = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[1])
        .await?;

    info!("Balance of sender: {acc_1_balance:#?}");
    info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_1_balance.balance, 9900);
    assert_eq!(acc_2_balance.balance, 20100);

    // WAIT
    info!("Waiting for indexer to parse blocks");
    tokio::time::sleep(std::time::Duration::from_millis(L2_TO_L1_TIMEOUT_MILLIS)).await;

    let acc1_ind_state = ctx
        .indexer_client()
        .get_account(ctx.existing_public_accounts()[0].into())
        .await
        .unwrap();
    let acc2_ind_state = ctx
        .indexer_client()
        .get_account(ctx.existing_public_accounts()[1].into())
        .await
        .unwrap();

    info!("Checking correct state transition");
    let acc1_seq_state = ctx
        .sequencer_client()
        .get_account(ctx.existing_public_accounts()[0])
        .await?
        .account;
    let acc2_seq_state = ctx
        .sequencer_client()
        .get_account(ctx.existing_public_accounts()[1])
        .await?
        .account;

    assert_eq!(acc1_ind_state, acc1_seq_state.into());
    assert_eq!(acc2_ind_state, acc2_seq_state.into());

    // ToDo: Check private state transition

    Ok(())
}
