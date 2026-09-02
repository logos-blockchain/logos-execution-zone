#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{io::Write as _, time::Duration};

use anyhow::Result;
use common::transaction::LeeTransaction;
use integration_tests::{TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, get_account, new_account};
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use tokio::test;
use wallet::{cli::Command, config::WalletConfigOverrides};

#[test]
async fn deploy_and_execute_program() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let deployed = test_programs::data_writer();
    let mut tempfile = tempfile::NamedTempFile::new()?;
    tempfile.write_all(deployed.elf())?;

    let binary_filepath = tempfile.path().to_owned();

    let command = Command::DeployProgram {
        binary_filepath: binary_filepath.clone(),
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    let account_id = new_account(&mut ctx, false, None).await?;

    let nonces = ctx.wallet_mut().get_accounts_nonces(&[account_id]).await?;
    let private_key = ctx
        .wallet()
        .get_account_public_signing_key(account_id)
        .unwrap();
    let written: Vec<u8> = vec![9; 4];
    let message = lee::public_transaction::Message::try_new(
        deployed.id(),
        vec![account_id],
        nonces,
        written.clone(),
    )?;
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[private_key]);
    let transaction = lee::PublicTransaction::new(message, witness_set);
    let _response = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::Public(transaction))
        .await?;

    log::info!("Waiting for next block creation");
    // Waiting for long time as it may take some time for such a big transaction to be included in a
    // block
    tokio::time::sleep(Duration::from_secs(2 * TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let post_state_account = get_account(&ctx, account_id).await?;

    assert_eq!(post_state_account.program_owner, deployed.id().into());
    assert_eq!(post_state_account.balance, 0);
    assert_eq!(post_state_account.data.as_ref(), written.as_slice());
    assert_eq!(post_state_account.nonce.0, 1);

    log::info!("Successfully deployed and executed program");

    Ok(())
}

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
