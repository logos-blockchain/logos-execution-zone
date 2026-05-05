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
    verify_commitment_is_in_state,
};
use log::info;
use nssa::AccountId;
use wallet::{
    account::Label,
    cli::{CliAccountMention, Command, programs::native_token_transfer::AuthTransferSubcommand},
};

/// Maximum time to wait for the indexer to catch up to the sequencer.
const L2_TO_L1_TIMEOUT_MILLIS: u64 = 180_000;

/// Poll the indexer until its last finalized block id reaches the sequencer's
/// current last block id or until [`L2_TO_L1_TIMEOUT_MILLIS`] elapses.
/// Returns the last indexer block id observed.
async fn wait_for_indexer_to_catch_up(ctx: &TestContext) -> Result<u64> {
    let timeout = Duration::from_millis(L2_TO_L1_TIMEOUT_MILLIS);
    let block_id_to_catch_up =
        sequencer_service_rpc::RpcClient::get_last_block_id(ctx.sequencer_client()).await?;
    let mut last_ind: u64 = 1;
    let inner = async {
        loop {
            let ind = ctx
                .indexer_client()
                .get_last_finalized_block_id()
                .await?
                .unwrap_or(0);
            last_ind = ind;
            if ind >= block_id_to_catch_up {
                let last_seq =
                    sequencer_service_rpc::RpcClient::get_last_block_id(ctx.sequencer_client())
                        .await?;
                info!(
                    "Indexer caught up. Indexer last block id: {ind}. Current sequencer last block id: {last_seq}"
                );
                return Ok(ind);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };
    tokio::time::timeout(timeout, inner)
        .await
        .with_context(|| {
            format!(
                "Indexer failed to catch up within {L2_TO_L1_TIMEOUT_MILLIS} milliseconds. Last indexer block id observed: {last_ind}, but needed to catch up to at least {block_id_to_catch_up}"
            )
        })?
}

#[tokio::test]
async fn indexer_test_run() -> Result<()> {
    let ctx = TestContext::new().await?;

    let last_block_indexer = wait_for_indexer_to_catch_up(&ctx).await?;

    let last_block_seq =
        sequencer_service_rpc::RpcClient::get_last_block_id(ctx.sequencer_client()).await?;

    info!("Last block on seq now is {last_block_seq}");
    info!("Last block on ind now is {last_block_indexer}");

    assert!(last_block_indexer > 0);

    Ok(())
}

#[tokio::test]
async fn indexer_block_batching() -> Result<()> {
    let ctx = TestContext::new().await?;

    info!("Waiting for indexer to parse blocks");
    let last_block_indexer = wait_for_indexer_to_catch_up(&ctx).await?;

    info!("Last block on ind now is {last_block_indexer}");

    assert!(last_block_indexer > 0);

    // Getting wide batch to fit all blocks (from latest backwards)
    let mut block_batch = ctx.indexer_client().get_blocks(None, 100).await.unwrap();

    // Reverse to check chain consistency from oldest to newest
    block_batch.reverse();

    // Checking chain consistency
    let mut prev_block_hash = block_batch.first().unwrap().header.hash;

    for block in &block_batch[1..] {
        assert_eq!(block.header.prev_block_hash, prev_block_hash);

        info!("Block {} chain-consistent", block.header.block_id);

        prev_block_hash = block.header.hash;
    }

    Ok(())
}

#[tokio::test]
async fn indexer_state_consistency() -> Result<()> {
    let mut ctx = TestContext::new().await?;

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: public_mention(ctx.existing_public_accounts()[0]),
        to: Some(public_mention(ctx.existing_public_accounts()[1])),
        to_npk: None,
        to_vpk: None,
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
