#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, format_private_account_id,
    format_public_account_id, verify_commitment_is_in_state,
};
use key_protocol::key_management::key_tree::chain_index::ChainIndex;
use log::info;
use nssa::program::Program;
use token_core::{TokenDefinition, TokenHolding};
use tokio::test;
use wallet::cli::{
    Command, SubcommandReturnValue,
    account::{AccountSubcommand, NewSubcommand},
    programs::token::TokenProgramAgnosticSubcommand,
};

#[test]
async fn create_and_transfer_public_token() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Create new account for the token definition
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: definition_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create new account for the token supply holder
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: supply_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create new account for receiving a token transaction
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: recipient_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create new token
    let name = "A NAME".to_owned();
    let total_supply = 37;
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id: format_public_account_id(definition_account_id),
        supply_account_id: format_public_account_id(supply_account_id),
        name: name.clone(),
        total_supply,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Check the status of the token definition account
    let definition_acc = ctx
        .sequencer_client()
        .get_account(definition_account_id)
        .await?
        .account;
    let token_definition = TokenDefinition::try_from(&definition_acc.data)?;

    assert_eq!(definition_acc.program_owner, Program::token().id());
    assert_eq!(
        token_definition,
        TokenDefinition::Fungible {
            name: name.clone(),
            total_supply,
            metadata_id: None
        }
    );

    // Check the status of the token holding account with the total supply
    let supply_acc = ctx
        .sequencer_client()
        .get_account(supply_account_id)
        .await?
        .account;

    // The account must be owned by the token program
    assert_eq!(supply_acc.program_owner, Program::token().id());
    let token_holding = TokenHolding::try_from(&supply_acc.data)?;
    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: total_supply
        }
    );

    // Transfer 7 tokens from supply_acc to recipient_account_id
    let transfer_amount = 7;
    let subcommand = TokenProgramAgnosticSubcommand::Send {
        from: format_public_account_id(supply_account_id),
        to: Some(format_public_account_id(recipient_account_id)),
        to_npk: None,
        to_vpk: None,
        amount: transfer_amount,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Check the status of the supply account after transfer
    let supply_acc = ctx
        .sequencer_client()
        .get_account(supply_account_id)
        .await?
        .account;
    assert_eq!(supply_acc.program_owner, Program::token().id());
    let token_holding = TokenHolding::try_from(&supply_acc.data)?;
    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: total_supply - transfer_amount
        }
    );

    // Check the status of the recipient account after transfer
    let recipient_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id)
        .await?
        .account;
    assert_eq!(recipient_acc.program_owner, Program::token().id());
    let token_holding = TokenHolding::try_from(&recipient_acc.data)?;
    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: transfer_amount
        }
    );

    // Burn 3 tokens from recipient_acc
    let burn_amount = 3;
    let subcommand = TokenProgramAgnosticSubcommand::Burn {
        definition: format_public_account_id(definition_account_id),
        holder: format_public_account_id(recipient_account_id),
        amount: burn_amount,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Check the status of the token definition account after burn
    let definition_acc = ctx
        .sequencer_client()
        .get_account(definition_account_id)
        .await?
        .account;
    let token_definition = TokenDefinition::try_from(&definition_acc.data)?;

    assert_eq!(
        token_definition,
        TokenDefinition::Fungible {
            name: name.clone(),
            total_supply: total_supply - burn_amount,
            metadata_id: None
        }
    );

    // Check the status of the recipient account after burn
    let recipient_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id)
        .await?
        .account;
    let token_holding = TokenHolding::try_from(&recipient_acc.data)?;

    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: transfer_amount - burn_amount
        }
    );

    // Mint 10 tokens at recipient_acc
    let mint_amount = 10;
    let subcommand = TokenProgramAgnosticSubcommand::Mint {
        definition: format_public_account_id(definition_account_id),
        holder: Some(format_public_account_id(recipient_account_id)),
        holder_npk: None,
        holder_vpk: None,
        amount: mint_amount,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Check the status of the token definition account after mint
    let definition_acc = ctx
        .sequencer_client()
        .get_account(definition_account_id)
        .await?
        .account;
    let token_definition = TokenDefinition::try_from(&definition_acc.data)?;

    assert_eq!(
        token_definition,
        TokenDefinition::Fungible {
            name,
            total_supply: total_supply - burn_amount + mint_amount,
            metadata_id: None
        }
    );

    // Check the status of the recipient account after mint
    let recipient_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id)
        .await?
        .account;
    let token_holding = TokenHolding::try_from(&recipient_acc.data)?;

    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: transfer_amount - burn_amount + mint_amount
        }
    );

    info!("Successfully created and transferred public token");

    Ok(())
}

#[test]
async fn create_and_transfer_token_with_private_supply() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Create new account for the token definition (public)
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: definition_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create new account for the token supply holder (private)
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: supply_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create new account for receiving a token transaction (private)
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: recipient_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create new token
    let name = "A NAME".to_owned();
    let total_supply = 37;
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id: format_public_account_id(definition_account_id),
        supply_account_id: format_private_account_id(supply_account_id),
        name: name.clone(),
        total_supply,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Check the status of the token definition account
    let definition_acc = ctx
        .sequencer_client()
        .get_account(definition_account_id)
        .await?
        .account;
    let token_definition = TokenDefinition::try_from(&definition_acc.data)?;

    assert_eq!(definition_acc.program_owner, Program::token().id());
    assert_eq!(
        token_definition,
        TokenDefinition::Fungible {
            name: name.clone(),
            total_supply,
            metadata_id: None
        }
    );

    let new_commitment1 = ctx
        .wallet()
        .get_private_account_commitment(supply_account_id)
        .context("Failed to get supply account commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment1, ctx.sequencer_client()).await);

    // Transfer 7 tokens from supply_acc to recipient_account_id
    let transfer_amount = 7;
    let subcommand = TokenProgramAgnosticSubcommand::Send {
        from: format_private_account_id(supply_account_id),
        to: Some(format_private_account_id(recipient_account_id)),
        to_npk: None,
        to_vpk: None,
        amount: transfer_amount,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let new_commitment1 = ctx
        .wallet()
        .get_private_account_commitment(supply_account_id)
        .context("Failed to get supply account commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment1, ctx.sequencer_client()).await);

    let new_commitment2 = ctx
        .wallet()
        .get_private_account_commitment(recipient_account_id)
        .context("Failed to get recipient account commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment2, ctx.sequencer_client()).await);

    // Burn 3 tokens from recipient_acc
    let burn_amount = 3;
    let subcommand = TokenProgramAgnosticSubcommand::Burn {
        definition: format_public_account_id(definition_account_id),
        holder: format_private_account_id(recipient_account_id),
        amount: burn_amount,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Check the token definition account after burn
    let definition_acc = ctx
        .sequencer_client()
        .get_account(definition_account_id)
        .await?
        .account;
    let token_definition = TokenDefinition::try_from(&definition_acc.data)?;

    assert_eq!(
        token_definition,
        TokenDefinition::Fungible {
            name,
            total_supply: total_supply - burn_amount,
            metadata_id: None
        }
    );

    let new_commitment2 = ctx
        .wallet()
        .get_private_account_commitment(recipient_account_id)
        .context("Failed to get recipient account commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment2, ctx.sequencer_client()).await);

    // Check the recipient account balance after burn
    let recipient_acc = ctx
        .wallet()
        .get_account_private(recipient_account_id)
        .context("Failed to get recipient account")?;
    let token_holding = TokenHolding::try_from(&recipient_acc.data)?;

    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: transfer_amount - burn_amount
        }
    );

    info!("Successfully created and transferred token with private supply");

    Ok(())
}

#[test]
async fn create_token_with_private_definition() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Create token definition account (private)
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: Some(ChainIndex::root()),
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: definition_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create supply account (public)
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: Some(ChainIndex::root()),
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: supply_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create token with private definition
    let name = "A NAME".to_owned();
    let total_supply = 37;
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id: format_private_account_id(definition_account_id),
        supply_account_id: format_public_account_id(supply_account_id),
        name: name.clone(),
        total_supply,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify private definition commitment
    let new_commitment = ctx
        .wallet()
        .get_private_account_commitment(definition_account_id)
        .context("Failed to get definition commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment, ctx.sequencer_client()).await);

    // Verify supply account
    let supply_acc = ctx
        .sequencer_client()
        .get_account(supply_account_id)
        .await?
        .account;

    assert_eq!(supply_acc.program_owner, Program::token().id());
    let token_holding = TokenHolding::try_from(&supply_acc.data)?;
    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: total_supply
        }
    );

    // Create private recipient account
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: recipient_account_id_private,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create public recipient account
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: recipient_account_id_public,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Mint to public account
    let mint_amount_public = 10;
    let subcommand = TokenProgramAgnosticSubcommand::Mint {
        definition: format_private_account_id(definition_account_id),
        holder: Some(format_public_account_id(recipient_account_id_public)),
        holder_npk: None,
        holder_vpk: None,
        amount: mint_amount_public,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify definition account has updated supply
    let definition_acc = ctx
        .wallet()
        .get_account_private(definition_account_id)
        .context("Failed to get definition account")?;
    let token_definition = TokenDefinition::try_from(&definition_acc.data)?;

    assert_eq!(
        token_definition,
        TokenDefinition::Fungible {
            name: name.clone(),
            total_supply: total_supply + mint_amount_public,
            metadata_id: None
        }
    );

    // Verify public recipient received tokens
    let recipient_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id_public)
        .await?
        .account;
    let token_holding = TokenHolding::try_from(&recipient_acc.data)?;

    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: mint_amount_public
        }
    );

    // Mint to private account
    let mint_amount_private = 5;
    let subcommand = TokenProgramAgnosticSubcommand::Mint {
        definition: format_private_account_id(definition_account_id),
        holder: Some(format_private_account_id(recipient_account_id_private)),
        holder_npk: None,
        holder_vpk: None,
        amount: mint_amount_private,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify private recipient commitment
    let new_commitment = ctx
        .wallet()
        .get_private_account_commitment(recipient_account_id_private)
        .context("Failed to get recipient commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment, ctx.sequencer_client()).await);

    // Verify private recipient balance
    let recipient_acc_private = ctx
        .wallet()
        .get_account_private(recipient_account_id_private)
        .context("Failed to get private recipient account")?;
    let token_holding = TokenHolding::try_from(&recipient_acc_private.data)?;

    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: mint_amount_private
        }
    );

    info!("Successfully created token with private definition and minted to both account types");

    Ok(())
}

#[test]
async fn create_token_with_private_definition_and_supply() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Create token definition account (private)
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: definition_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create supply account (private)
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: supply_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create token with both private definition and supply
    let name = "A NAME".to_owned();
    let total_supply = 37;
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id: format_private_account_id(definition_account_id),
        supply_account_id: format_private_account_id(supply_account_id),
        name,
        total_supply,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify definition commitment
    let definition_commitment = ctx
        .wallet()
        .get_private_account_commitment(definition_account_id)
        .context("Failed to get definition commitment")?;
    assert!(verify_commitment_is_in_state(definition_commitment, ctx.sequencer_client()).await);

    // Verify supply commitment
    let supply_commitment = ctx
        .wallet()
        .get_private_account_commitment(supply_account_id)
        .context("Failed to get supply commitment")?;
    assert!(verify_commitment_is_in_state(supply_commitment, ctx.sequencer_client()).await);

    // Verify supply balance
    let supply_acc = ctx
        .wallet()
        .get_account_private(supply_account_id)
        .context("Failed to get supply account")?;
    let token_holding = TokenHolding::try_from(&supply_acc.data)?;

    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: total_supply
        }
    );

    // Create recipient account
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: recipient_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Transfer tokens
    let transfer_amount = 7;
    let subcommand = TokenProgramAgnosticSubcommand::Send {
        from: format_private_account_id(supply_account_id),
        to: Some(format_private_account_id(recipient_account_id)),
        to_npk: None,
        to_vpk: None,
        amount: transfer_amount,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify both commitments updated
    let supply_commitment = ctx
        .wallet()
        .get_private_account_commitment(supply_account_id)
        .context("Failed to get supply commitment")?;
    assert!(verify_commitment_is_in_state(supply_commitment, ctx.sequencer_client()).await);

    let recipient_commitment = ctx
        .wallet()
        .get_private_account_commitment(recipient_account_id)
        .context("Failed to get recipient commitment")?;
    assert!(verify_commitment_is_in_state(recipient_commitment, ctx.sequencer_client()).await);

    // Verify balances
    let supply_acc = ctx
        .wallet()
        .get_account_private(supply_account_id)
        .context("Failed to get supply account")?;
    let token_holding = TokenHolding::try_from(&supply_acc.data)?;
    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: total_supply - transfer_amount
        }
    );

    let recipient_acc = ctx
        .wallet()
        .get_account_private(recipient_account_id)
        .context("Failed to get recipient account")?;
    let token_holding = TokenHolding::try_from(&recipient_acc.data)?;
    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: transfer_amount
        }
    );

    info!("Successfully created and transferred token with both private definition and supply");

    Ok(())
}

#[test]
async fn shielded_token_transfer() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Create token definition account (public)
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: definition_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create supply account (public)
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: supply_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create recipient account (private) for shielded transfer
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: recipient_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create token
    let name = "A NAME".to_owned();
    let total_supply = 37;
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id: format_public_account_id(definition_account_id),
        supply_account_id: format_public_account_id(supply_account_id),
        name,
        total_supply,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Perform shielded transfer: public supply -> private recipient
    let transfer_amount = 7;
    let subcommand = TokenProgramAgnosticSubcommand::Send {
        from: format_public_account_id(supply_account_id),
        to: Some(format_private_account_id(recipient_account_id)),
        to_npk: None,
        to_vpk: None,
        amount: transfer_amount,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify supply account balance
    let supply_acc = ctx
        .sequencer_client()
        .get_account(supply_account_id)
        .await?
        .account;
    let token_holding = TokenHolding::try_from(&supply_acc.data)?;
    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: total_supply - transfer_amount
        }
    );

    // Verify recipient commitment exists
    let new_commitment = ctx
        .wallet()
        .get_private_account_commitment(recipient_account_id)
        .context("Failed to get recipient commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment, ctx.sequencer_client()).await);

    // Verify recipient balance
    let recipient_acc = ctx
        .wallet()
        .get_account_private(recipient_account_id)
        .context("Failed to get recipient account")?;
    let token_holding = TokenHolding::try_from(&recipient_acc.data)?;
    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: transfer_amount
        }
    );

    info!("Successfully performed shielded token transfer");

    Ok(())
}

#[test]
async fn deshielded_token_transfer() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Create token definition account (public)
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: definition_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create supply account (private)
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: supply_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create recipient account (public) for deshielded transfer
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: recipient_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create token with private supply
    let name = "A NAME".to_owned();
    let total_supply = 37;
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id: format_public_account_id(definition_account_id),
        supply_account_id: format_private_account_id(supply_account_id),
        name,
        total_supply,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Perform deshielded transfer: private supply -> public recipient
    let transfer_amount = 7;
    let subcommand = TokenProgramAgnosticSubcommand::Send {
        from: format_private_account_id(supply_account_id),
        to: Some(format_public_account_id(recipient_account_id)),
        to_npk: None,
        to_vpk: None,
        amount: transfer_amount,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Verify supply account commitment exists
    let new_commitment = ctx
        .wallet()
        .get_private_account_commitment(supply_account_id)
        .context("Failed to get supply commitment")?;
    assert!(verify_commitment_is_in_state(new_commitment, ctx.sequencer_client()).await);

    // Verify supply balance
    let supply_acc = ctx
        .wallet()
        .get_account_private(supply_account_id)
        .context("Failed to get supply account")?;
    let token_holding = TokenHolding::try_from(&supply_acc.data)?;
    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: total_supply - transfer_amount
        }
    );

    // Verify recipient balance
    let recipient_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id)
        .await?
        .account;
    let token_holding = TokenHolding::try_from(&recipient_acc.data)?;
    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: transfer_amount
        }
    );

    info!("Successfully performed deshielded token transfer");

    Ok(())
}

#[test]
async fn token_claiming_path_with_private_accounts() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Create token definition account (private)
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: definition_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create supply account (private)
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: supply_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create token
    let name = "A NAME".to_owned();
    let total_supply = 37;
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id: format_private_account_id(definition_account_id),
        supply_account_id: format_private_account_id(supply_account_id),
        name,
        total_supply,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Create new private account for claiming path
    let result = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Private {
            cci: None,
            label: None,
        })),
    )
    .await?;
    let SubcommandReturnValue::RegisterAccount {
        account_id: recipient_account_id,
    } = result
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Get keys for foreign mint (claiming path)
    let (holder_keys, _) = ctx
        .wallet()
        .storage()
        .user_data
        .get_private_account(recipient_account_id)
        .cloned()
        .context("Failed to get private account keys")?;

    // Mint using claiming path (foreign account)
    let mint_amount = 9;
    let subcommand = TokenProgramAgnosticSubcommand::Mint {
        definition: format_private_account_id(definition_account_id),
        holder: None,
        holder_npk: Some(hex::encode(holder_keys.nullifer_public_key.0)),
        holder_vpk: Some(hex::encode(holder_keys.viewing_public_key.0)),
        amount: mint_amount,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Sync to claim the account
    let command = Command::Account(AccountSubcommand::SyncPrivate {});
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    // Verify commitment exists
    let recipient_commitment = ctx
        .wallet()
        .get_private_account_commitment(recipient_account_id)
        .context("Failed to get recipient commitment")?;
    assert!(verify_commitment_is_in_state(recipient_commitment, ctx.sequencer_client()).await);

    // Verify balance
    let recipient_acc = ctx
        .wallet()
        .get_account_private(recipient_account_id)
        .context("Failed to get recipient account")?;
    let token_holding = TokenHolding::try_from(&recipient_acc.data)?;
    assert_eq!(
        token_holding,
        TokenHolding::Fungible {
            definition_id: definition_account_id,
            balance: mint_amount
        }
    );

    info!("Successfully minted tokens using claiming path");

    Ok(())
}
