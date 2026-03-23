#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::Result;
use integration_tests::{TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, format_public_account_id};
use log::info;
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::cli::{
    Command, SubcommandReturnValue,
    account::{AccountSubcommand, NewSubcommand},
    programs::{amm::AmmProgramAgnosticSubcommand, token::TokenProgramAgnosticSubcommand},
};

#[test]
async fn amm_public() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Create new account for the token definition
    let SubcommandReturnValue::RegisterAccount {
        account_id: definition_account_id_1,
    } = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create new account for the token supply holder
    let SubcommandReturnValue::RegisterAccount {
        account_id: supply_account_id_1,
    } = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create new account for receiving a token transaction
    let SubcommandReturnValue::RegisterAccount {
        account_id: recipient_account_id_1,
    } = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create new account for the token definition
    let SubcommandReturnValue::RegisterAccount {
        account_id: definition_account_id_2,
    } = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create new account for the token supply holder
    let SubcommandReturnValue::RegisterAccount {
        account_id: supply_account_id_2,
    } = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create new account for receiving a token transaction
    let SubcommandReturnValue::RegisterAccount {
        account_id: recipient_account_id_2,
    } = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create new token
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id: format_public_account_id(definition_account_id_1),
        supply_account_id: format_public_account_id(supply_account_id_1),
        name: "A NAM1".to_owned(),
        total_supply: 37,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Transfer 7 tokens from `supply_acc` to the account at account_id `recipient_account_id_1`
    let subcommand = TokenProgramAgnosticSubcommand::Send {
        from: format_public_account_id(supply_account_id_1),
        to: Some(format_public_account_id(recipient_account_id_1)),
        to_npk: None,
        to_vpk: None,
        amount: 7,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Create new token
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id: format_public_account_id(definition_account_id_2),
        supply_account_id: format_public_account_id(supply_account_id_2),
        name: "A NAM2".to_owned(),
        total_supply: 37,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Transfer 7 tokens from `supply_acc` to the account at account_id `recipient_account_id_2`
    let subcommand = TokenProgramAgnosticSubcommand::Send {
        from: format_public_account_id(supply_account_id_2),
        to: Some(format_public_account_id(recipient_account_id_2)),
        to_npk: None,
        to_vpk: None,
        amount: 7,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("=================== SETUP FINISHED ===============");

    // Create new AMM

    // Setup accounts
    // Create new account for the user holding lp
    let SubcommandReturnValue::RegisterAccount {
        account_id: user_holding_lp,
    } = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: None,
        })),
    )
    .await?
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Send creation tx
    let subcommand = AmmProgramAgnosticSubcommand::New {
        user_holding_a: format_public_account_id(recipient_account_id_1),
        user_holding_b: format_public_account_id(recipient_account_id_2),
        user_holding_lp: format_public_account_id(user_holding_lp),
        balance_a: 3,
        balance_b: 3,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::AMM(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let user_holding_a_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id_1)
        .await?;

    let user_holding_b_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id_2)
        .await?;

    let user_holding_lp_acc = ctx.sequencer_client().get_account(user_holding_lp).await?;

    assert_eq!(
        u128::from_le_bytes(user_holding_a_acc.data[33..].try_into().unwrap()),
        4
    );

    assert_eq!(
        u128::from_le_bytes(user_holding_b_acc.data[33..].try_into().unwrap()),
        4
    );

    assert_eq!(
        u128::from_le_bytes(user_holding_lp_acc.data[33..].try_into().unwrap()),
        3
    );

    info!("=================== AMM DEFINITION FINISHED ===============");

    // Make swap

    let subcommand = AmmProgramAgnosticSubcommand::Swap {
        user_holding_a: format_public_account_id(recipient_account_id_1),
        user_holding_b: format_public_account_id(recipient_account_id_2),
        amount_in: 2,
        min_amount_out: 1,
        token_definition: definition_account_id_1.to_string(),
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::AMM(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let user_holding_a_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id_1)
        .await?;

    let user_holding_b_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id_2)
        .await?;

    let user_holding_lp_acc = ctx.sequencer_client().get_account(user_holding_lp).await?;

    assert_eq!(
        u128::from_le_bytes(user_holding_a_acc.data[33..].try_into().unwrap()),
        2
    );

    assert_eq!(
        u128::from_le_bytes(user_holding_b_acc.data[33..].try_into().unwrap()),
        5
    );

    assert_eq!(
        u128::from_le_bytes(user_holding_lp_acc.data[33..].try_into().unwrap()),
        3
    );

    info!("=================== FIRST SWAP FINISHED ===============");

    // Make swap

    let subcommand = AmmProgramAgnosticSubcommand::Swap {
        user_holding_a: format_public_account_id(recipient_account_id_1),
        user_holding_b: format_public_account_id(recipient_account_id_2),
        amount_in: 2,
        min_amount_out: 1,
        token_definition: definition_account_id_2.to_string(),
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::AMM(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let user_holding_a_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id_1)
        .await?;

    let user_holding_b_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id_2)
        .await?;

    let user_holding_lp_acc = ctx.sequencer_client().get_account(user_holding_lp).await?;

    assert_eq!(
        u128::from_le_bytes(user_holding_a_acc.data[33..].try_into().unwrap()),
        4
    );

    assert_eq!(
        u128::from_le_bytes(user_holding_b_acc.data[33..].try_into().unwrap()),
        3
    );

    assert_eq!(
        u128::from_le_bytes(user_holding_lp_acc.data[33..].try_into().unwrap()),
        3
    );

    info!("=================== SECOND SWAP FINISHED ===============");

    // Add liquidity

    let subcommand = AmmProgramAgnosticSubcommand::AddLiquidity {
        user_holding_a: format_public_account_id(recipient_account_id_1),
        user_holding_b: format_public_account_id(recipient_account_id_2),
        user_holding_lp: format_public_account_id(user_holding_lp),
        min_amount_lp: 1,
        max_amount_a: 2,
        max_amount_b: 2,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::AMM(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let user_holding_a_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id_1)
        .await?;

    let user_holding_b_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id_2)
        .await?;

    let user_holding_lp_acc = ctx.sequencer_client().get_account(user_holding_lp).await?;

    assert_eq!(
        u128::from_le_bytes(user_holding_a_acc.data[33..].try_into().unwrap()),
        3
    );

    assert_eq!(
        u128::from_le_bytes(user_holding_b_acc.data[33..].try_into().unwrap()),
        1
    );

    assert_eq!(
        u128::from_le_bytes(user_holding_lp_acc.data[33..].try_into().unwrap()),
        4
    );

    info!("=================== ADD LIQ FINISHED ===============");

    // Remove liquidity

    let subcommand = AmmProgramAgnosticSubcommand::RemoveLiquidity {
        user_holding_a: format_public_account_id(recipient_account_id_1),
        user_holding_b: format_public_account_id(recipient_account_id_2),
        user_holding_lp: format_public_account_id(user_holding_lp),
        balance_lp: 2,
        min_amount_a: 1,
        min_amount_b: 1,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::AMM(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let user_holding_a_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id_1)
        .await?;

    let user_holding_b_acc = ctx
        .sequencer_client()
        .get_account(recipient_account_id_2)
        .await?;

    let user_holding_lp_acc = ctx.sequencer_client().get_account(user_holding_lp).await?;

    assert_eq!(
        u128::from_le_bytes(user_holding_a_acc.data[33..].try_into().unwrap()),
        5
    );

    assert_eq!(
        u128::from_le_bytes(user_holding_b_acc.data[33..].try_into().unwrap()),
        4
    );

    assert_eq!(
        u128::from_le_bytes(user_holding_lp_acc.data[33..].try_into().unwrap()),
        2
    );

    info!("Success!");

    Ok(())
}
