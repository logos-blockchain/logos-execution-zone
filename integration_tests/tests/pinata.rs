use std::time::Duration;

use anyhow::{Context as _, Result};
use common::PINATA_BASE58;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, format_private_account_id,
    format_public_account_id, verify_commitment_is_in_state,
};
use log::info;
use tokio::test;
use wallet::cli::{
    Command, SubcommandReturnValue,
    account::{AccountSubcommand, NewSubcommand},
    programs::{
        native_token_transfer::AuthTransferSubcommand, pinata::PinataProgramAgnosticSubcommand,
    },
};

#[test]
async fn claim_pinata_to_uninitialized_public_account_fails_fast() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: winner_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    let winner_account_id_formatted = format_public_account_id(winner_account_id);

    let pinata_balance_pre = ctx
        .sequencer_client()
        .get_account_balance(PINATA_BASE58.parse().unwrap())
        .await?
        .balance;

    let claim_result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Pinata(PinataProgramAgnosticSubcommand::Claim {
            to: winner_account_id_formatted,
        }),
    )
    .await;

    assert!(
        claim_result.is_err(),
        "Expected uninitialized account error"
    );
    let err = claim_result.unwrap_err().to_string();
    assert!(
        err.contains("wallet auth-transfer init --account-id Public/"),
        "Expected init guidance, got: {err}",
    );

    let pinata_balance_post = ctx
        .sequencer_client()
        .get_account_balance(PINATA_BASE58.parse().unwrap())
        .await?
        .balance;

    assert_eq!(pinata_balance_post, pinata_balance_pre);

    Ok(())
}

#[test]
async fn claim_pinata_to_uninitialized_private_account_fails_fast() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: winner_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    let winner_account_id_formatted = format_private_account_id(winner_account_id);

    let pinata_balance_pre = ctx
        .sequencer_client()
        .get_account_balance(PINATA_BASE58.parse().unwrap())
        .await?
        .balance;

    let claim_result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Pinata(PinataProgramAgnosticSubcommand::Claim {
            to: winner_account_id_formatted,
        }),
    )
    .await;

    assert!(
        claim_result.is_err(),
        "Expected uninitialized account error"
    );
    let err = claim_result.unwrap_err().to_string();
    assert!(
        err.contains("wallet auth-transfer init --account-id Private/"),
        "Expected init guidance, got: {err}",
    );

    let pinata_balance_post = ctx
        .sequencer_client()
        .get_account_balance(PINATA_BASE58.parse().unwrap())
        .await?
        .balance;

    assert_eq!(pinata_balance_post, pinata_balance_pre);

    Ok(())
}

#[test]
async fn claim_pinata_to_existing_public_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let pinata_prize = 150;
    let command = Command::Pinata(PinataProgramAgnosticSubcommand::Claim {
        to: format_public_account_id(ctx.existing_public_accounts()[0]),
    });

    let pinata_balance_pre = ctx
        .sequencer_client()
        .get_account_balance(PINATA_BASE58.parse().unwrap())
        .await?
        .balance;

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move");
    let pinata_balance_post = ctx
        .sequencer_client()
        .get_account_balance(PINATA_BASE58.parse().unwrap())
        .await?
        .balance;

    let winner_balance_post = ctx
        .sequencer_client()
        .get_account_balance(ctx.existing_public_accounts()[0])
        .await?
        .balance;

    assert_eq!(pinata_balance_post, pinata_balance_pre - pinata_prize);
    assert_eq!(winner_balance_post, 10000 + pinata_prize);

    info!("Successfully claimed pinata to public account");

    Ok(())
}

#[test]
async fn claim_pinata_to_existing_private_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let pinata_prize = 150;
    let command = Command::Pinata(PinataProgramAgnosticSubcommand::Claim {
        to: format_private_account_id(ctx.existing_private_accounts()[0]),
    });

    let pinata_balance_pre = ctx
        .sequencer_client()
        .get_account_balance(PINATA_BASE58.parse().unwrap())
        .await?
        .balance;

    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    let SubcommandReturnValue::PrivacyPreservingTransfer { tx_hash: _ } = result else {
        anyhow::bail!("Expected PrivacyPreservingTransfer return value");
    };

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Syncing private accounts");
    let command = Command::Account(AccountSubcommand::SyncPrivate {});
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    let new_commitment = ctx
        .wallet()
        .get_private_account_commitment(ctx.existing_private_accounts()[0])
        .context("Failed to get private account commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment, ctx.sequencer_client()).await);

    let pinata_balance_post = ctx
        .sequencer_client()
        .get_account_balance(PINATA_BASE58.parse().unwrap())
        .await?
        .balance;

    assert_eq!(pinata_balance_post, pinata_balance_pre - pinata_prize);

    info!("Successfully claimed pinata to existing private account");

    Ok(())
}

#[test]
async fn claim_pinata_to_new_private_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let pinata_prize = 150;

    // Create new private account
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: winner_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    let winner_account_id_formatted = format_private_account_id(winner_account_id);

    // Initialize account under auth transfer program
    let command = Command::AuthTransfer(AuthTransferSubcommand::Init {
        account_id: winner_account_id_formatted.clone(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let new_commitment = ctx
        .wallet()
        .get_private_account_commitment(winner_account_id)
        .context("Failed to get private account commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment, ctx.sequencer_client()).await);

    // Claim pinata to the new private account
    let command = Command::Pinata(PinataProgramAgnosticSubcommand::Claim {
        to: winner_account_id_formatted,
    });

    let pinata_balance_pre = ctx
        .sequencer_client()
        .get_account_balance(PINATA_BASE58.parse().unwrap())
        .await?
        .balance;

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let new_commitment = ctx
        .wallet()
        .get_private_account_commitment(winner_account_id)
        .context("Failed to get private account commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment, ctx.sequencer_client()).await);

    let pinata_balance_post = ctx
        .sequencer_client()
        .get_account_balance(PINATA_BASE58.parse().unwrap())
        .await?
        .balance;

    assert_eq!(pinata_balance_post, pinata_balance_pre - pinata_prize);

    info!("Successfully claimed pinata to new private account");

    Ok(())
}
