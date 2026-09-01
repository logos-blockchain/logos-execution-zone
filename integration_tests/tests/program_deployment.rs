#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{io::Write as _, time::Duration};

use anyhow::Result;
use integration_tests::TIME_TO_WAIT_FOR_BLOCK_SECONDS;
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use tokio::test;
use wallet::{cli::Command, config::WalletConfigOverrides};

#[test]
async fn deploy_invalid_program_fails() -> Result<()> {
    // An invalid program bytecode is rejected by the sequencer during block production, so the
    // deployment transaction is never included in a block. Shrink the wallet's polling window so
    // the command gives up quickly instead of waiting for the full default timeout.

    let mut ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_wallet_config_overrides(WalletConfigOverrides {
                    seq_poll_timeout: Some(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)),
                    seq_tx_poll_max_blocks: Some(5),
                    seq_poll_max_retries: Some(2),
                    ..WalletConfigOverrides::default()
                }),
        )
        .build()
        .await?;

    let mut tempfile = tempfile::NamedTempFile::new()?;
    tempfile.write_all(b"this is not a valid program binary")?;

    let command = Command::DeployProgram {
        binary_filepath: tempfile.path().to_owned(),
    };

    let result = wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await;

    assert!(
        result.is_err(),
        "Deploying an invalid program should fail, but got: {result:?}"
    );

    log::info!("Deploying an invalid program failed as expected");

    Ok(())
}
