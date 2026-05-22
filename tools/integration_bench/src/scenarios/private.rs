//! Private chained flow: shielded, deshielded, and private-to-private transfers.

use anyhow::{Result, bail};
use test_fixtures::{TestContext, private_mention, public_mention};
use wallet::cli::{
    Command, SubcommandReturnValue,
    account::{AccountSubcommand, NewSubcommand},
    programs::token::TokenProgramAgnosticSubcommand,
};

use crate::harness::ScenarioOutput;

pub async fn run(ctx: &mut TestContext) -> Result<ScenarioOutput> {
    let mut output = ScenarioOutput::new("private_chained_flow");

    let def_id = new_public_account(ctx, &mut output, "create_acc_def").await?;
    let supply_id = new_public_account(ctx, &mut output, "create_acc_supply").await?;
    let public_recipient_id =
        new_public_account(ctx, &mut output, "create_acc_pub_recipient").await?;
    let private_a = new_private_account(ctx, &mut output, "create_acc_priv_a").await?;
    let private_b = new_private_account(ctx, &mut output, "create_acc_priv_b").await?;

    // Mint into public supply.
    output
        .step(ctx, "token_new_fungible", async |ctx| {
            wallet::cli::execute_subcommand(
                ctx.wallet_mut(),
                Command::Token(TokenProgramAgnosticSubcommand::New {
                    definition_account_id: public_mention(def_id),
                    supply_account_id: public_mention(supply_id),
                    name: "PrivToken".to_owned(),
                    total_supply: 1_000_000,
                }),
            )
            .await
        })
        .await?;

    // Shielded transfer: public supply -> private_a.
    output
        .step(ctx, "shielded_transfer", async |ctx| {
            wallet::cli::execute_subcommand(
                ctx.wallet_mut(),
                Command::Token(TokenProgramAgnosticSubcommand::Send {
                    from: public_mention(supply_id),
                    to: Some(private_mention(private_a)),
                    to_npk: None,
                    to_vpk: None,
                    to_identifier: Some(0),
                    amount: 1_000,
                }),
            )
            .await
        })
        .await?;

    // Deshielded transfer: private_a -> public_recipient.
    output
        .step(ctx, "deshielded_transfer", async |ctx| {
            wallet::cli::execute_subcommand(
                ctx.wallet_mut(),
                Command::Token(TokenProgramAgnosticSubcommand::Send {
                    from: private_mention(private_a),
                    to: Some(public_mention(public_recipient_id)),
                    to_npk: None,
                    to_vpk: None,
                    to_identifier: Some(0),
                    amount: 100,
                }),
            )
            .await
        })
        .await?;

    // Private-to-private transfer: private_a -> private_b.
    output
        .step(ctx, "private_to_private", async |ctx| {
            wallet::cli::execute_subcommand(
                ctx.wallet_mut(),
                Command::Token(TokenProgramAgnosticSubcommand::Send {
                    from: private_mention(private_a),
                    to: Some(private_mention(private_b)),
                    to_npk: None,
                    to_vpk: None,
                    to_identifier: Some(0),
                    amount: 200,
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
