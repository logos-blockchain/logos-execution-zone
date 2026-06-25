#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{io::Write as _, time::Duration};

use anyhow::Result;
use common::transaction::LeeTransaction;
use integration_tests::{TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, get_account, new_account};
use log::info;
use sequencer_service_rpc::RpcClient as _;
use tokio::test;
use wallet::cli::Command;

#[test]
async fn deploy_and_execute_program() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let claimer = test_programs::claimer();
    let mut tempfile = tempfile::NamedTempFile::new()?;
    tempfile.write_all(claimer.elf())?;

    let binary_filepath = tempfile.path().to_owned();

    let command = Command::DeployProgram {
        binary_filepath: binary_filepath.clone(),
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let account_id = new_account(&mut ctx, false, None).await?;

    let nonces = ctx.wallet().get_accounts_nonces(vec![account_id]).await?;
    let private_key = ctx
        .wallet()
        .get_account_public_signing_key(account_id)
        .unwrap();
    let message =
        lee::public_transaction::Message::try_new(claimer.id(), vec![account_id], nonces, ())?;
    let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[private_key]);
    let transaction = lee::PublicTransaction::new(message, witness_set);
    let _response = ctx
        .sequencer_client()
        .send_transaction(LeeTransaction::Public(transaction))
        .await?;

    info!("Waiting for next block creation");
    // Waiting for long time as it may take some time for such a big transaction to be included in a
    // block
    tokio::time::sleep(Duration::from_secs(2 * TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let post_state_account = get_account(&ctx, account_id).await?;

    let expected_data: &[u8] = &[];
    assert_eq!(post_state_account.program_owner, claimer.id());
    assert_eq!(post_state_account.balance, 0);
    assert_eq!(post_state_account.data.as_ref(), expected_data);
    assert_eq!(post_state_account.nonce.0, 1);

    info!("Successfully deployed and executed program");

    Ok(())
}
