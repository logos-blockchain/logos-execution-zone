//! Token onboarding scenario: create accounts, mint, public transfer, private transfer.

use anyhow::{Result, bail};
use test_fixtures::{TestContext, private_mention, public_mention};
use wallet::cli::{
    Command, SubcommandReturnValue,
    account::{AccountSubcommand, NewSubcommand},
    programs::token::TokenProgramAgnosticSubcommand,
};

use crate::harness::ScenarioOutput;

pub async fn run(ctx: &mut TestContext) -> Result<ScenarioOutput> {
    let mut output = ScenarioOutput::new("token_onboarding");

    let definition_id = new_public_account(ctx, &mut output, "create_pub_definition").await?;
    let supply_id = new_public_account(ctx, &mut output, "create_pub_supply").await?;
    let recipient_id = new_public_account(ctx, &mut output, "create_pub_recipient").await?;

    output
        .step(ctx, "token_new_fungible", async |ctx| {
            wallet::cli::execute_subcommand(
                ctx.wallet_mut(),
                Command::Token(TokenProgramAgnosticSubcommand::New {
                    definition_account_id: public_mention(definition_id),
                    supply_account_id: public_mention(supply_id),
                    name: "BenchToken".to_owned(),
                    total_supply: 1_000_000,
                }),
            )
            .await
        })
        .await?;

    output
        .step(ctx, "token_public_transfer", async |ctx| {
            wallet::cli::execute_subcommand(
                ctx.wallet_mut(),
                Command::Token(TokenProgramAgnosticSubcommand::Send {
                    from: public_mention(supply_id),
                    to: Some(public_mention(recipient_id)),
                    to_npk: None,
                    to_vpk: None,
                    to_identifier: Some(0),
                    amount: 1_000,
                }),
            )
            .await
        })
        .await?;

    let private_recipient_id =
        new_private_account(ctx, &mut output, "create_priv_recipient").await?;

    output
        .step(ctx, "token_shielded_transfer", async |ctx| {
            wallet::cli::execute_subcommand(
                ctx.wallet_mut(),
                Command::Token(TokenProgramAgnosticSubcommand::Send {
                    from: public_mention(supply_id),
                    to: Some(private_mention(private_recipient_id)),
                    to_npk: None,
                    to_vpk: None,
                    to_identifier: Some(0),
                    amount: 500,
                }),
            )
            .await
        })
        .await?;

    Ok(output)
}

async fn new_public_account(
    ctx: &mut TestContext,
    output: &mut ScenarioOutput,
    label: &str,
) -> Result<nssa::AccountId> {
    let ret = output
        .step(ctx, label, async |ctx| {
            wallet::cli::execute_subcommand(
                ctx.wallet_mut(),
                Command::Account(AccountSubcommand::New(NewSubcommand::Public {
                    cci: None,
                    label: None,
                })),
            )
            .await
        })
        .await?;
    match ret {
        SubcommandReturnValue::RegisterAccount { account_id } => Ok(account_id),
        other => bail!("expected RegisterAccount, got {other:?}"),
    }
}

async fn new_private_account(
    ctx: &mut TestContext,
    output: &mut ScenarioOutput,
    label: &str,
) -> Result<nssa::AccountId> {
    let ret = output
        .step(ctx, label, async |ctx| {
            wallet::cli::execute_subcommand(
                ctx.wallet_mut(),
                Command::Account(AccountSubcommand::New(NewSubcommand::Private {
                    cci: None,
                    label: None,
                })),
            )
            .await
        })
        .await?;
    match ret {
        SubcommandReturnValue::RegisterAccount { account_id } => Ok(account_id),
        other => bail!("expected RegisterAccount, got {other:?}"),
    }
}
