#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::Result;
use indexer_service_rpc::RpcClient as _;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, public_mention, wait_for_indexer_to_catch_up,
};
use log::info;
use wallet::{
    account::Label,
    cli::{CliAccountMention, Command, programs::native_token_transfer::AuthTransferSubcommand},
};

#[tokio::test]
async fn indexer_state_consistency_with_labels() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    // Assign labels to both accounts
    let from_label = Label::new("idx-sender-label");
    let to_label = Label::new("idx-receiver-label");

    let label_cmd = Command::Account(wallet::cli::account::AccountSubcommand::Label {
        account_id: public_mention(ctx.existing_public_accounts()[0]),
        label: from_label.clone(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), label_cmd).await?;

    let label_cmd = Command::Account(wallet::cli::account::AccountSubcommand::Label {
        account_id: public_mention(ctx.existing_public_accounts()[1]),
        label: to_label.clone(),
    });
    wallet::cli::execute_subcommand(ctx.wallet_mut(), label_cmd).await?;

    // Send using labels instead of account IDs
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: CliAccountMention::Label(from_label),
        to: Some(CliAccountMention::Label(to_label)),
        to_npk: None,
        to_vpk: None,
        to_keys: None,
        to_identifier: Some(0),
        amount: 100,
    });

    wallet::cli::execute_subcommand(ctx.wallet_mut(), command).await?;

    info!("Waiting for next block creation");
    tokio::time::sleep(Duration::from_secs(TIME_TO_WAIT_FOR_BLOCK_SECONDS)).await;

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

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    info!("Waiting for indexer to parse blocks");
    wait_for_indexer_to_catch_up(&ctx).await?;

    let acc1_ind_state = ctx
        .indexer_client()
        .get_account(ctx.existing_public_accounts()[0].into())
        .await
        .unwrap();
    let acc1_seq_state = sequencer_service_rpc::RpcClient::get_account(
        ctx.sequencer_client(),
        ctx.existing_public_accounts()[0],
    )
    .await?;

    assert_eq!(acc1_ind_state, acc1_seq_state.into());

    info!("Indexer state is consistent after label-based transfer");

    Ok(())
}
