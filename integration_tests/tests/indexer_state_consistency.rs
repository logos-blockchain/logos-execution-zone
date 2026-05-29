#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use indexer_service_rpc::RpcClient as _;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, private_mention, public_mention,
    verify_commitment_is_in_state, wait_for_indexer_to_catch_up,
};
use lee::AccountId;
use log::info;
use wallet::cli::{Command, programs::native_token_transfer::AuthTransferSubcommand};

#[tokio::test]
async fn indexer_state_consistency() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: public_mention(ctx.existing_public_accounts()[0]),
        to: Some(public_mention(ctx.existing_public_accounts()[1])),
        to_npk: None,
        to_vpk: None,
        to_keys: None,
        to_identifier: Some(0),
        amount: 100,
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    info!("Checking correct balance move");
    let acc_1_balance = sequencer_service_rpc::RpcClient::get_account_balance(
        ctx.sequencer_client(),
        ctx.existing_public_accounts()[0],
    )
    .await?;
    let acc_2_balance = sequencer_service_rpc::RpcClient::get_account_balance(
        ctx.sequencer_client(),
        ctx.existing_public_accounts()[1],
    )
    .await?;

    info!("Balance of sender: {acc_1_balance:#?}");
    info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    let from: AccountId = ctx.existing_private_accounts()[0];
    let to: AccountId = ctx.existing_private_accounts()[1];

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: private_mention(from),
        to: Some(private_mention(to)),
        to_npk: None,
        to_vpk: None,
        to_keys: None,
        to_identifier: Some(0),
        amount: 100,
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

    let new_commitment1 = ctx
        .wallet()
        .get_private_account_commitment(from)
        .context("Failed to get private account commitment for sender")?;
    assert!(verify_commitment_is_in_state(new_commitment1, ctx.sequencer_client()).await);

    let new_commitment2 = ctx
        .wallet()
        .get_private_account_commitment(to)
        .context("Failed to get private account commitment for receiver")?;
    assert!(verify_commitment_is_in_state(new_commitment2, ctx.sequencer_client()).await);

    info!("Successfully transferred privately to owned account");

    info!("Waiting for indexer to parse blocks");
    wait_for_indexer_to_catch_up(&ctx).await?;

    let acc1_ind_state = ctx
        .indexer_client()
        .get_account(ctx.existing_public_accounts()[0].into())
        .await
        .unwrap();
    let acc2_ind_state = ctx
        .indexer_client()
        .get_account(ctx.existing_public_accounts()[1].into())
        .await
        .unwrap();

    info!("Checking correct state transition");
    let acc1_seq_state = sequencer_service_rpc::RpcClient::get_account(
        ctx.sequencer_client(),
        ctx.existing_public_accounts()[0],
    )
    .await?;
    let acc2_seq_state = sequencer_service_rpc::RpcClient::get_account(
        ctx.sequencer_client(),
        ctx.existing_public_accounts()[1],
    )
    .await?;

    assert_eq!(acc1_ind_state, acc1_seq_state.into());
    assert_eq!(acc2_ind_state, acc2_seq_state.into());

    // ToDo: Check private state transition

    Ok(())
}
