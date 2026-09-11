#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use integration_tests::{TestContext, public_mention, utils::send};
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder,
    config::{MultiNodeTestContextConfig, bedrock_channel_id},
};
use tokio::test;
use wallet::cli::{Command, config::ConfigSubcommand, statistics::StatisticsSubcommand};

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

    log::info!("Successfully modified and restored config field");

    Ok(())
}

#[test]
async fn modify_config_field_multiseq() -> Result<()> {
    let mut ctx = MultiZoneTestContextBuilder::default()
        .with_zone(ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
            num_nodes: 2,
            bedrock_channel: bedrock_channel_id(),
        }))
        .build()
        .await?;

    // Default config have callibration limit and distribution limit as 1
    // Modifying them
    let wallet_mut = ctx.wallet_mut();

    let command = Command::Config(ConfigSubcommand::Set {
        key: "distribution_limit".to_owned(),
        value: "2".to_owned(),
    });
    wallet::cli::execute_subcommand(wallet_mut, command).await?;

    let command = Command::Config(ConfigSubcommand::Set {
        key: "calibration_limit".to_owned(),
        value: "10".to_owned(),
    });
    wallet::cli::execute_subcommand(wallet_mut, command).await?;

    // Check config correctness
    assert_eq!(
        wallet_mut
            .config()
            .multi_sequencer_client_config
            .calibration_limit,
        10
    );
    assert_eq!(
        wallet_mut
            .config()
            .multi_sequencer_client_config
            .distribution_limit,
        2
    );

    // Rotate clients to callibrate the other one
    let command = Command::Statistics(StatisticsSubcommand::ExecuteRotation);
    wallet::cli::execute_subcommand(wallet_mut, command).await?;

    // After that, there must be two leaders
    let leaders = wallet_mut.leaders();
    assert_eq!(leaders.len(), 2);

    // And both of them must have similar statistics
    let first_stat = wallet_mut.get_statistics(&leaders[0].1).unwrap();
    let second_stat = wallet_mut.get_statistics(&leaders[1].1).unwrap();

    assert_eq!(first_stat.latest_block_id, second_stat.latest_block_id);

    Ok(())
}

#[test]
async fn transactions_declare_the_configured_gas_limit() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let accounts = ctx.existing_public_accounts();
    let from = accounts[0];
    let to = accounts[1];

    // One past the per-transaction ceiling, which the sequencer refuses before
    // it executes anything. Nothing else about a plain transfer can produce
    // that refusal, so it can only have come from the configured limit.
    let command = Command::Config(ConfigSubcommand::Set {
        key: "gas_limit".to_owned(),
        value: (fee_core::market::MAX_GAS_EXEC + 1).to_string(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;
    assert_eq!(
        ctx.wallet().config().gas_limit,
        fee_core::market::MAX_GAS_EXEC + 1
    );

    let over_cap = send(&mut ctx, public_mention(from), public_mention(to), 100).await;
    assert!(
        over_cap.is_err(),
        "a transfer declaring more gas than the per-transaction cap should be refused"
    );

    // The same transfer at the default limit, so the refusal above is the
    // declared gas and nothing else about these accounts.
    let command = Command::Config(ConfigSubcommand::Set {
        key: "gas_limit".to_owned(),
        value: wallet::DEFAULT_GAS_LIMIT.to_string(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    send(&mut ctx, public_mention(from), public_mention(to), 100).await?;

    Ok(())
}
