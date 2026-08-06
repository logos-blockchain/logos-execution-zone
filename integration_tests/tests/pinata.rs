#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, account_balance, new_account, private_mention,
    public_mention, sync_private, verify_commitment_is_in_state, wait_for_indexer_to_catch_up,
};
use log::info;
use tokio::test;
use wallet::cli::{
    Command, SubcommandReturnValue,
    programs::{
        native_token_transfer::AuthTransferSubcommand, pinata::PinataProgramAgnosticSubcommand,
    },
};

#[test]
async fn claim_pinata_to_existing_public_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let pinata_prize = 150;
    let command = Command::Pinata(PinataProgramAgnosticSubcommand::Claim {
        to: public_mention(ctx.existing_public_accounts()[0]),
    });

    let pinata_balance_pre = account_balance(&ctx, system_accounts::pinata_account_id()).await?;

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move");
    let pinata_balance_post = account_balance(&ctx, system_accounts::pinata_account_id()).await?;

    let winner_balance_post = account_balance(&ctx, ctx.existing_public_accounts()[0]).await?;

    assert_eq!(pinata_balance_post, pinata_balance_pre - pinata_prize);
    assert_eq!(winner_balance_post, 10000 + pinata_prize);

    info!("Successfully claimed pinata to public account");

    Ok(())
}

#[test]
async fn claim_pinata_indexer_keeps_up() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let command = Command::Pinata(PinataProgramAgnosticSubcommand::Claim {
        to: public_mention(ctx.existing_public_accounts()[0]),
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Waiting for indexer to parse blocks");
    wait_for_indexer_to_catch_up(&ctx).await?;

    let winner_ind_state = indexer_service_rpc::RpcClient::get_account(
        &**ctx.indexer_client(),
        ctx.existing_public_accounts()[0].into(),
    )
    .await
    .unwrap();
    let winner_seq_state = sequencer_service_rpc::RpcClient::get_account(
        ctx.sequencer_client(),
        ctx.existing_public_accounts()[0],
    )
    .await?;

    assert_eq!(winner_ind_state, winner_seq_state.into());

    info!("Indexer correctly indexed the pinata claim");

    Ok(())
}

#[test]
async fn claim_pinata_to_existing_private_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let pinata_prize = 150;
    let command = Command::Pinata(PinataProgramAgnosticSubcommand::Claim {
        to: private_mention(ctx.existing_private_accounts()[0]),
    });

    let pinata_balance_pre = account_balance(&ctx, system_accounts::pinata_account_id()).await?;

    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::TransactionExecuted { tx_hash: _ } = result else {
        anyhow::bail!("Expected TransactionExecuted return value");
    };

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Syncing private accounts");
    sync_private(&mut ctx).await?;

    let new_commitment = ctx
        .wallet()
        .get_private_account_commitment(ctx.existing_private_accounts()[0])
        .context("Failed to get private account commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment, ctx.sequencer_client()).await);

    let pinata_balance_post = account_balance(&ctx, system_accounts::pinata_account_id()).await?;

    assert_eq!(pinata_balance_post, pinata_balance_pre - pinata_prize);

    info!("Successfully claimed pinata to existing private account");

    Ok(())
}

#[test]
async fn claim_pinata_to_new_private_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let pinata_prize = 150;

    // Create new private account
    let winner_account_id = new_account(&mut ctx, true, None).await?;

    let funder = ctx.existing_public_accounts()[0];
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: public_mention(funder),
        to: Some(private_mention(winner_account_id)),
        to_npk: None,
        to_vpk: None,
        to_keys: None,
        to_identifier: None,
        amount: 1,
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;
    sync_private(&mut ctx).await?;

    let new_commitment = ctx
        .wallet()
        .get_private_account_commitment(winner_account_id)
        .context("Failed to get private account commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment, ctx.sequencer_client()).await);

    // Claim pinata to the new private account
    let command = Command::Pinata(PinataProgramAgnosticSubcommand::Claim {
        to: private_mention(winner_account_id),
    });

    let pinata_balance_pre = account_balance(&ctx, system_accounts::pinata_account_id()).await?;

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let new_commitment = ctx
        .wallet()
        .get_private_account_commitment(winner_account_id)
        .context("Failed to get private account commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment, ctx.sequencer_client()).await);

    let pinata_balance_post = account_balance(&ctx, system_accounts::pinata_account_id()).await?;

    assert_eq!(pinata_balance_post, pinata_balance_pre - pinata_prize);

    info!("Successfully claimed pinata to new private account");

    Ok(())
}
