//! Private chained flow: shielded, deshielded, and private-to-private transfers.

use anyhow::{Result, bail};
use test_fixtures::{TestContext, private_mention, public_mention};
use wallet::cli::{
    Command, SubcommandReturnValue,
    account::{AccountSubcommand, NewSubcommand},
    programs::native_token_transfer::AuthTransferSubcommand,
};

use crate::harness::ScenarioOutput;

pub async fn run(ctx: &mut TestContext) -> Result<ScenarioOutput> {
    let mut output = ScenarioOutput::new("private_chained_flow");

    // Preconfigured account with a lot of native tokens.
    let supply_id = *ctx
        .existing_public_accounts()
        .first()
        .ok_or_else(|| anyhow::anyhow!("At least one public account must exist"))?;

    let private_a = new_private_account(ctx, &mut output, "create_acc_priv_a").await?;
    let private_b = new_private_account(ctx, &mut output, "create_acc_priv_b").await?;

    // Shielded fund of a private_a account.
    output
        .step(ctx, "fund_private_account", async |ctx| {
            wallet::cli::execute_subcommand(
                ctx.wallet_mut(),
                Command::AuthTransfer(AuthTransferSubcommand::Send {
                    from: public_mention(supply_id),
                    to: Some(private_mention(private_a)),
                    to_npk: None,
                    to_vpk: None,
                    to_keys: None,
                    to_identifier: Some(0),
                    amount: 1_000,
                }),
            )
            .await
        })
        .await?;

    // Deshielded transfer: private_a -> supply_id.
    output
        .step(ctx, "deshielded_transfer", async |ctx| {
            wallet::cli::execute_subcommand(
                ctx.wallet_mut(),
                Command::AuthTransfer(AuthTransferSubcommand::Send {
                    from: private_mention(private_a),
                    to: Some(public_mention(supply_id)),
                    to_npk: None,
                    to_vpk: None,
                    to_keys: None,
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
                Command::AuthTransfer(AuthTransferSubcommand::Send {
                    from: private_mention(private_a),
                    to: Some(private_mention(private_b)),
                    to_npk: None,
                    to_vpk: None,
                    to_keys: None,
                    to_identifier: Some(0),
                    amount: 200,
                }),
            )
            .await
        })
        .await?;

    Ok(output)
}

async fn new_private_account(
    ctx: &mut TestContext,
    output: &mut ScenarioOutput,
    label: &str,
) -> Result<lee::AccountId> {
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
