#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use ata_core::{compute_ata_seed, get_associated_token_account_id};
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, format_private_account_id,
    format_public_account_id, verify_commitment_is_in_state,
};
use log::info;
use nssa::program::Program;
use sequencer_service_rpc::RpcClient as _;
use token_core::{TokenDefinition, TokenHolding};
use tokio::test;
use wallet::cli::{
    Command, SubcommandReturnValue,
    account::{AccountSubcommand, NewSubcommand},
    programs::{ata::AtaSubcommand, token::TokenProgramAgnosticSubcommand},
};

/// Create a public account and return its ID.
async fn new_public_account(ctx: &mut TestContext) -> Result<nssa::AccountId> {
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount { account_id } = result else {
        anyhow::bail!("Expected RegisterAccount return value");
    };
    Ok(account_id)
}

/// Create a private account and return its ID.
async fn new_private_account(ctx: &mut TestContext) -> Result<nssa::AccountId> {
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount { account_id } = result else {
        anyhow::bail!("Expected RegisterAccount return value");
    };
    Ok(account_id)
}

#[test]
async fn create_ata_initializes_holding_account() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let definition_account_id = new_public_account(&mut ctx).await?;
    let supply_account_id = new_public_account(&mut ctx).await?;
    let owner_account_id = new_public_account(&mut ctx).await?;

    // Create a fungible token
    let total_supply = 100_u128;
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Token(TokenProgramAgnosticSubcommand::New {
            definition_account_id: format_public_account_id(definition_account_id),
            supply_account_id: format_public_account_id(supply_account_id),
            name: "TEST".to_owned(),
            total_supply,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Create the ATA for owner + definition
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Ata(AtaSubcommand::Create {
            owner: format_public_account_id(owner_account_id),
            token_definition: definition_account_id.to_string(),
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Derive expected ATA address and check on-chain state
    let ata_program_id = Program::ata().id();
    let ata_id = get_associated_token_account_id(
        &ata_program_id,
        &compute_ata_seed(owner_account_id, definition_account_id),
    );

    let ata_acc = ctx
        .sequencer_client()
        .get_account(ata_id)
        .await
        .context("ATA account not found")?;

    assert_eq!(ata_acc.program_owner, Program::token().id());
    let holding = TokenHolding::try_from(&ata_acc.data)?;
    assert_eq!(
        holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: 0,
        }
    );

    Ok(())
}

#[test]
async fn create_ata_is_idempotent() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let definition_account_id = new_public_account(&mut ctx).await?;
    let supply_account_id = new_public_account(&mut ctx).await?;
    let owner_account_id = new_public_account(&mut ctx).await?;

    // Create a fungible token
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Token(TokenProgramAgnosticSubcommand::New {
            definition_account_id: format_public_account_id(definition_account_id),
            supply_account_id: format_public_account_id(supply_account_id),
            name: "TEST".to_owned(),
            total_supply: 100,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Create the ATA once
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Ata(AtaSubcommand::Create {
            owner: format_public_account_id(owner_account_id),
            token_definition: definition_account_id.to_string(),
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Create the ATA a second time — must succeed (idempotent)
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Ata(AtaSubcommand::Create {
            owner: format_public_account_id(owner_account_id),
            token_definition: definition_account_id.to_string(),
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // State must be unchanged
    let ata_program_id = Program::ata().id();
    let ata_id = get_associated_token_account_id(
        &ata_program_id,
        &compute_ata_seed(owner_account_id, definition_account_id),
    );

    let ata_acc = ctx
        .sequencer_client()
        .get_account(ata_id)
        .await
        .context("ATA account not found")?;

    assert_eq!(ata_acc.program_owner, Program::token().id());
    let holding = TokenHolding::try_from(&ata_acc.data)?;
    assert_eq!(
        holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: 0,
        }
    );

    Ok(())
}

#[test]
async fn transfer_and_burn_via_ata() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let definition_account_id = new_public_account(&mut ctx).await?;
    let supply_account_id = new_public_account(&mut ctx).await?;
    let sender_account_id = new_public_account(&mut ctx).await?;
    let recipient_account_id = new_public_account(&mut ctx).await?;

    let total_supply = 1000_u128;

    // Create a fungible token, supply goes to supply_account_id
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Token(TokenProgramAgnosticSubcommand::New {
            definition_account_id: format_public_account_id(definition_account_id),
            supply_account_id: format_public_account_id(supply_account_id),
            name: "TEST".to_owned(),
            total_supply,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Derive ATA addresses
    let ata_program_id = Program::ata().id();
    let sender_ata_id = get_associated_token_account_id(
        &ata_program_id,
        &compute_ata_seed(sender_account_id, definition_account_id),
    );
    let recipient_ata_id = get_associated_token_account_id(
        &ata_program_id,
        &compute_ata_seed(recipient_account_id, definition_account_id),
    );

    // Create ATAs for sender and recipient
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Ata(AtaSubcommand::Create {
            owner: format_public_account_id(sender_account_id),
            token_definition: definition_account_id.to_string(),
        }),
    )
    .await?;
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Ata(AtaSubcommand::Create {
            owner: format_public_account_id(recipient_account_id),
            token_definition: definition_account_id.to_string(),
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Fund sender's ATA from the supply account (direct token transfer)
    let fund_amount = 200_u128;
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Token(TokenProgramAgnosticSubcommand::Send {
            from: format_public_account_id(supply_account_id),
            to: Some(format_public_account_id(sender_ata_id)),
            to_npk: None,
            to_vpk: None,
            amount: fund_amount,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Transfer from sender's ATA to recipient's ATA via the ATA program
    let transfer_amount = 50_u128;
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Ata(AtaSubcommand::Send {
            from: format_public_account_id(sender_account_id),
            token_definition: definition_account_id.to_string(),
            to: recipient_ata_id.to_string(),
            amount: transfer_amount,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify sender ATA balance decreased
    let sender_ata_acc = ctx.sequencer_client().get_account(sender_ata_id).await?;
    let sender_holding = TokenHolding::try_from(&sender_ata_acc.data)?;
    assert_eq!(
        sender_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: fund_amount - transfer_amount,
        }
    );

    // Verify recipient ATA balance increased
    let recipient_ata_acc = ctx.sequencer_client().get_account(recipient_ata_id).await?;
    let recipient_holding = TokenHolding::try_from(&recipient_ata_acc.data)?;
    assert_eq!(
        recipient_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: transfer_amount,
        }
    );

    // Burn from sender's ATA
    let burn_amount = 30_u128;
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Ata(AtaSubcommand::Burn {
            holder: format_public_account_id(sender_account_id),
            token_definition: definition_account_id.to_string(),
            amount: burn_amount,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify sender ATA balance after burn
    let sender_ata_acc = ctx.sequencer_client().get_account(sender_ata_id).await?;
    let sender_holding = TokenHolding::try_from(&sender_ata_acc.data)?;
    assert_eq!(
        sender_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: fund_amount - transfer_amount - burn_amount,
        }
    );

    // Verify the token definition total_supply decreased by burn_amount
    let definition_acc = ctx
        .sequencer_client()
        .get_account(definition_account_id)
        .await?;
    let token_definition = TokenDefinition::try_from(&definition_acc.data)?;
    assert_eq!(
        token_definition,
        TokenDefinition::Fungible {
            name: "TEST".to_owned(),
            total_supply: total_supply - burn_amount,
            metadata_id: None,
        }
    );

    Ok(())
}

#[test]
async fn create_ata_with_private_owner() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let definition_account_id = new_public_account(&mut ctx).await?;
    let supply_account_id = new_public_account(&mut ctx).await?;
    let owner_account_id = new_private_account(&mut ctx).await?;

    // Create a fungible token
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Token(TokenProgramAgnosticSubcommand::New {
            definition_account_id: format_public_account_id(definition_account_id),
            supply_account_id: format_public_account_id(supply_account_id),
            name: "TEST".to_owned(),
            total_supply: 100,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Create the ATA for the private owner + definition
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Ata(AtaSubcommand::Create {
            owner: format_private_account_id(owner_account_id),
            token_definition: definition_account_id.to_string(),
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Derive expected ATA address and check on-chain state
    let ata_program_id = Program::ata().id();
    let ata_id = get_associated_token_account_id(
        &ata_program_id,
        &compute_ata_seed(owner_account_id, definition_account_id),
    );

    let ata_acc = ctx
        .sequencer_client()
        .get_account(ata_id)
        .await
        .context("ATA account not found")?;

    assert_eq!(ata_acc.program_owner, Program::token().id());
    let holding = TokenHolding::try_from(&ata_acc.data)?;
    assert_eq!(
        holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: 0,
        }
    );

    // Verify the private owner's commitment is in state
    let commitment = ctx
        .wallet()
        .get_private_account_commitment(owner_account_id)
        .context("Private owner commitment not found")?;
    assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);

    Ok(())
}

#[test]
async fn transfer_via_ata_private_owner() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let definition_account_id = new_public_account(&mut ctx).await?;
    let supply_account_id = new_public_account(&mut ctx).await?;
    let sender_account_id = new_private_account(&mut ctx).await?;
    let recipient_account_id = new_public_account(&mut ctx).await?;

    let total_supply = 1000_u128;

    // Create a fungible token
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Token(TokenProgramAgnosticSubcommand::New {
            definition_account_id: format_public_account_id(definition_account_id),
            supply_account_id: format_public_account_id(supply_account_id),
            name: "TEST".to_owned(),
            total_supply,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Derive ATA addresses
    let ata_program_id = Program::ata().id();
    let sender_ata_id = get_associated_token_account_id(
        &ata_program_id,
        &compute_ata_seed(sender_account_id, definition_account_id),
    );
    let recipient_ata_id = get_associated_token_account_id(
        &ata_program_id,
        &compute_ata_seed(recipient_account_id, definition_account_id),
    );

    // Create ATAs for sender (private owner) and recipient (public owner)
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Ata(AtaSubcommand::Create {
            owner: format_private_account_id(sender_account_id),
            token_definition: definition_account_id.to_string(),
        }),
    )
    .await?;
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Ata(AtaSubcommand::Create {
            owner: format_public_account_id(recipient_account_id),
            token_definition: definition_account_id.to_string(),
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Fund sender's ATA from the supply account (direct token transfer)
    let fund_amount = 200_u128;
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Token(TokenProgramAgnosticSubcommand::Send {
            from: format_public_account_id(supply_account_id),
            to: Some(format_public_account_id(sender_ata_id)),
            to_npk: None,
            to_vpk: None,
            amount: fund_amount,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Transfer from sender's ATA (private owner) to recipient's ATA
    let transfer_amount = 50_u128;
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Ata(AtaSubcommand::Send {
            from: format_private_account_id(sender_account_id),
            token_definition: definition_account_id.to_string(),
            to: recipient_ata_id.to_string(),
            amount: transfer_amount,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify sender ATA balance decreased
    let sender_ata_acc = ctx.sequencer_client().get_account(sender_ata_id).await?;
    let sender_holding = TokenHolding::try_from(&sender_ata_acc.data)?;
    assert_eq!(
        sender_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: fund_amount - transfer_amount,
        }
    );

    // Verify recipient ATA balance increased
    let recipient_ata_acc = ctx.sequencer_client().get_account(recipient_ata_id).await?;
    let recipient_holding = TokenHolding::try_from(&recipient_ata_acc.data)?;
    assert_eq!(
        recipient_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: transfer_amount,
        }
    );

    // Verify the private sender's commitment is in state
    let commitment = ctx
        .wallet()
        .get_private_account_commitment(sender_account_id)
        .context("Private sender commitment not found")?;
    assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);

    Ok(())
}

#[test]
async fn burn_via_ata_private_owner() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let definition_account_id = new_public_account(&mut ctx).await?;
    let supply_account_id = new_public_account(&mut ctx).await?;
    let holder_account_id = new_private_account(&mut ctx).await?;

    let total_supply = 500_u128;

    // Create a fungible token
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Token(TokenProgramAgnosticSubcommand::New {
            definition_account_id: format_public_account_id(definition_account_id),
            supply_account_id: format_public_account_id(supply_account_id),
            name: "TEST".to_owned(),
            total_supply,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Derive holder's ATA address
    let ata_program_id = Program::ata().id();
    let holder_ata_id = get_associated_token_account_id(
        &ata_program_id,
        &compute_ata_seed(holder_account_id, definition_account_id),
    );

    // Create ATA for the private holder
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Ata(AtaSubcommand::Create {
            owner: format_private_account_id(holder_account_id),
            token_definition: definition_account_id.to_string(),
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Fund holder's ATA from the supply account
    let fund_amount = 300_u128;
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Token(TokenProgramAgnosticSubcommand::Send {
            from: format_public_account_id(supply_account_id),
            to: Some(format_public_account_id(holder_ata_id)),
            to_npk: None,
            to_vpk: None,
            amount: fund_amount,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Burn from holder's ATA (private owner)
    let burn_amount = 100_u128;
    wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Ata(AtaSubcommand::Burn {
            holder: format_private_account_id(holder_account_id),
            token_definition: definition_account_id.to_string(),
            amount: burn_amount,
        }),
    )
    .await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify holder ATA balance after burn
    let holder_ata_acc = ctx.sequencer_client().get_account(holder_ata_id).await?;
    let holder_holding = TokenHolding::try_from(&holder_ata_acc.data)?;
    assert_eq!(
        holder_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: fund_amount - burn_amount,
        }
    );

    // Verify the token definition total_supply decreased by burn_amount
    let definition_acc = ctx
        .sequencer_client()
        .get_account(definition_account_id)
        .await?;
    let token_definition = TokenDefinition::try_from(&definition_acc.data)?;
    assert_eq!(
        token_definition,
        TokenDefinition::Fungible {
            name: "TEST".to_owned(),
            total_supply: total_supply - burn_amount,
            metadata_id: None,
        }
    );

    // Verify the private holder's commitment is in state
    let commitment = ctx
        .wallet()
        .get_private_account_commitment(holder_account_id)
        .context("Private holder commitment not found")?;
    assert!(verify_commitment_is_in_state(commitment, ctx.sequencer_client()).await);

    Ok(())
}
