#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::Result;
use integration_tests::{TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, public_mention};
use log::info;
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::{
    account::Label,
    cli::{
        Command, SubcommandReturnValue,
        account::{AccountSubcommand, NewSubcommand},
        programs::{amm::AmmProgramAgnosticSubcommand, token::TokenProgramAgnosticSubcommand},
    },
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
        definition_account_id: public_mention(definition_account_id_1),
        supply_account_id: public_mention(supply_account_id_1),
        name: "A NAM1".to_owned(),

        total_supply: 37,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Transfer 7 tokens from `supply_acc` to the account at account_id `recipient_account_id_1`
    let subcommand = TokenProgramAgnosticSubcommand::Send {
        from: public_mention(supply_account_id_1),
        to: Some(public_mention(recipient_account_id_1)),
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
        amount: 7,
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Create new token
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id: public_mention(definition_account_id_2),
        supply_account_id: public_mention(supply_account_id_2),
        name: "A NAM2".to_owned(),

        total_supply: 37,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Transfer 7 tokens from `supply_acc` to the account at account_id `recipient_account_id_2`
    let subcommand = TokenProgramAgnosticSubcommand::Send {
        from: public_mention(supply_account_id_2),
        to: Some(public_mention(recipient_account_id_2)),
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
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
        user_holding_a: public_mention(recipient_account_id_1),
        user_holding_b: public_mention(recipient_account_id_2),
        user_holding_lp: public_mention(user_holding_lp),
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

    let subcommand = AmmProgramAgnosticSubcommand::SwapExactInput {
        user_holding_a: public_mention(recipient_account_id_1),
        user_holding_b: public_mention(recipient_account_id_2),
        amount_in: 2,
        min_amount_out: 1,
        token_definition: definition_account_id_1,
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

    let subcommand = AmmProgramAgnosticSubcommand::SwapExactInput {
        user_holding_a: public_mention(recipient_account_id_1),
        user_holding_b: public_mention(recipient_account_id_2),
        amount_in: 2,
        min_amount_out: 1,
        token_definition: definition_account_id_2,
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
        user_holding_a: public_mention(recipient_account_id_1),
        user_holding_b: public_mention(recipient_account_id_2),
        user_holding_lp: public_mention(user_holding_lp),
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
        user_holding_a: public_mention(recipient_account_id_1),
        user_holding_b: public_mention(recipient_account_id_2),
        user_holding_lp: public_mention(user_holding_lp),
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

#[test]
async fn amm_new_pool_using_labels() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Create token 1 accounts
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

    // Create holding_a with a label
    let holding_a_label = Label::new("amm-holding-a-label");
    let SubcommandReturnValue::RegisterAccount {
        account_id: holding_a_id,
    } = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: Some(Label::new(holding_a_label.clone())),
        })),
    )
    .await?
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create token 2 accounts
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

    // Create holding_b with a label
    let holding_b_label = Label::new("amm-holding-b-label");
    let SubcommandReturnValue::RegisterAccount {
        account_id: holding_b_id,
    } = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: Some(Label::new(holding_b_label.clone())),
        })),
    )
    .await?
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create holding_lp with a label
    let holding_lp_label = Label::new("amm-holding-lp-label");
    let SubcommandReturnValue::RegisterAccount {
        account_id: holding_lp_id,
    } = wallet::cli::execute_subcommand(
        ctx.wallet_mut(),
        Command::Account(AccountSubcommand::New(NewSubcommand::Public {
            cci: None,
            label: Some(Label::new(holding_lp_label.clone())),
        })),
    )
    .await?
    else {
        anyhow::bail!("Expected RegisterAccount return value");
    };

    // Create token 1 and distribute to holding_a
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id: public_mention(definition_account_id_1),
        supply_account_id: public_mention(supply_account_id_1),
        name: "TOKEN1".to_owned(),
        total_supply: 10,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let subcommand = TokenProgramAgnosticSubcommand::Send {
        from: public_mention(supply_account_id_1),
        to: Some(public_mention(holding_a_id)),
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
        amount: 5,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Create token 2 and distribute to holding_b
    let subcommand = TokenProgramAgnosticSubcommand::New {
        definition_account_id: public_mention(definition_account_id_2),
        supply_account_id: public_mention(supply_account_id_2),
        name: "TOKEN2".to_owned(),
        total_supply: 10,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let subcommand = TokenProgramAgnosticSubcommand::Send {
        from: public_mention(supply_account_id_2),
        to: Some(public_mention(holding_b_id)),
        to_npk: None,
        to_vpk: None,
        to_identifier: Some(0),
        amount: 5,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::Token(subcommand)).await?;
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // Create AMM pool using account labels instead of IDs
    let subcommand = AmmProgramAgnosticSubcommand::New {
        user_holding_a: holding_a_label.into(),
        user_holding_b: holding_b_label.into(),
        user_holding_lp: holding_lp_label.into(),
        balance_a: 3,
        balance_b: 3,
    };
    wallet::cli::execute_subcommand(ctx.wallet_mut(), Command::AMM(subcommand)).await?;
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let holding_lp_acc = ctx.sequencer_client().get_account(holding_lp_id).await?;

    // LP balance should be 3 (geometric mean of 3, 3)
    assert_eq!(
        u128::from_le_bytes(holding_lp_acc.data[33..].try_into().unwrap()),
        3
    );

    info!("Successfully created AMM pool using account labels");

    Ok(())
}
