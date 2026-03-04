#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use integration_tests::{
    NSSA_PROGRAM_FOR_TEST_DATA_CHANGER, TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext,
};
use log::info;
use nssa::{AccountId, program::Program};
use tokio::test;
use wallet::cli::Command;

#[test]
async fn deploy_and_execute_program() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let binary_filepath: PathBuf = PathBuf::from(manifest_dir)
        .join("../artifacts/test_program_methods")
        .join(NSSA_PROGRAM_FOR_TEST_DATA_CHANGER);

    let command = Command::DeployProgram {
        binary_filepath: binary_filepath.clone(),
    };

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    // The program is the data changer and takes one account as input.
    // We pass an uninitialized account and we expect after execution to be owned by the data
    // changer program (NSSA account claiming mechanism) with data equal to [0] (due to program
    // logic)
    let bytecode = std::fs::read(binary_filepath)?;
    let data_changer = Program::new(bytecode)?;
    let account_id: AccountId = "11".repeat(16).parse()?;
    let message = nssa::public_transaction::Message::try_new(
        data_changer.id(),
        vec![account_id],
        vec![],
        vec![0],
    )?;
    let witness_set = nssa::public_transaction::WitnessSet::for_message(&message, &[]);
    let transaction = nssa::PublicTransaction::new(message, witness_set);
    let _response = ctx.sequencer_client().send_tx_public(transaction).await?;

    info!("Waiting for next block creation");
    // Waiting for long time as it may take some time for such a big transaction to be included in a
    // block
    tokio::time::sleep(Duration::from_secs(2 * TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let post_state_account = ctx
        .sequencer_client()
        .get_account(account_id)
        .await?
        .account;

    assert_eq!(post_state_account.program_owner, data_changer.id());
    assert_eq!(post_state_account.balance, 0);
    assert_eq!(post_state_account.data.as_ref(), &[0]);
    assert_eq!(post_state_account.nonce, 0);

    info!("Successfully deployed and executed program");

    Ok(())
}
