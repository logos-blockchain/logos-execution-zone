#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use integration_tests::TestContext;
use log::info;
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

    info!("Successfully modified and restored config field");

    Ok(())
}
