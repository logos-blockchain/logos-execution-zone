#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use integration_tests::{TestContext, public_mention, utils::send};
use tokio::test;
use wallet::cli::{Command, config::ConfigSubcommand};

#[test]
async fn modify_config_field() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let old_seq_poll_timeout = ctx.wallet().config().seq_poll_timeout;

    // Change config field
    let command = Command::Config(ConfigSubcommand::Set {
        key: "seq_poll_timeout".to_owned(),
        value: "1s".to_owned(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    let new_seq_poll_timeout = ctx.wallet().config().seq_poll_timeout;
    assert_eq!(new_seq_poll_timeout, std::time::Duration::from_secs(1));

    // Return how it was at the beginning
    let command = Command::Config(ConfigSubcommand::Set {
        key: "seq_poll_timeout".to_owned(),
        value: format!("{old_seq_poll_timeout:?}"),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    tracing::info!("Successfully modified and restored config field");

    Ok(())
}

#[test]
async fn a_gas_limit_above_the_per_transaction_cap_is_clamped() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let accounts = ctx.existing_public_accounts();
    let from = accounts[0];
    let to = accounts[1];
    let over_cap = fee_core::market::MAX_GAS_EXEC + 1;

    // The configured limit is the ceiling of a measured one, held to the cap the sequencer
    // enforces.
    let command = Command::Config(ConfigSubcommand::Set {
        key: "gas_limit".to_owned(),
        value: over_cap.to_string(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    assert_eq!(ctx.wallet().config().gas_limit, over_cap);
    send(&mut ctx, public_mention(from), public_mention(to), 100).await?;

    // An explicit limit is declared as given, held to the same cap: unclamped, the sequencer
    // refuses it before executing anything.
    ctx.wallet_mut().set_fee_params(wallet::FeeParams {
        gas_limit: Some(over_cap),
        ..wallet::FeeParams::default()
    });
    send(&mut ctx, public_mention(from), public_mention(to), 100).await?;

    Ok(())
}
