#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::{Context as _, Result};
use indexer_ffi::{IndexerServiceFFI, OperationStatus, api::PointerResult};
use indexer_service_rpc::RpcClient as _;
use integration_tests::{
    TIME_TO_WAIT_FOR_BLOCK_SECONDS, format_private_account_id, format_public_account_id,
    test_context_ffi::BlockingTestContextFFI, verify_commitment_is_in_state,
};
use log::info;
use nssa::AccountId;
use wallet::cli::{Command, programs::native_token_transfer::AuthTransferSubcommand};

/// Maximum time to wait for the indexer to catch up to the sequencer.
const L2_TO_L1_TIMEOUT_MILLIS: u64 = 180_000;

unsafe extern "C" {
    unsafe fn query_last_block(
        indexer: *const IndexerServiceFFI,
    ) -> PointerResult<u64, OperationStatus>;
}

#[test]
fn indexer_test_run_ffi() -> Result<()> {
    let blocking_ctx = BlockingTestContextFFI::new()?;
    let runtime_wrapped = blocking_ctx.runtime();

    // RUN OBSERVATION
    runtime_wrapped.block_on(async {
        tokio::time::sleep(std::time::Duration::from_millis(L2_TO_L1_TIMEOUT_MILLIS)).await;
    });

    let last_block_indexer = blocking_ctx.ctx().get_last_block_indexer(runtime_wrapped)?;
    let last_block_indexer_ffi_res = unsafe { query_last_block(blocking_ctx.indexer_ffi()) };

    assert!(last_block_indexer_ffi_res.error.is_ok());

    let last_block_indexer_ffi = unsafe { *last_block_indexer_ffi_res.value };

    info!("Last block on ind now is {last_block_indexer}");
    info!("Last block on ind ffi now is {last_block_indexer_ffi}");

    assert!(last_block_indexer > 1);
    assert!(last_block_indexer_ffi > 1);

    assert_eq!(last_block_indexer, last_block_indexer_ffi);

    Ok(())
}

#[test]
fn indexer_ffi_block_batching() -> Result<()> {
    let blocking_ctx = BlockingTestContextFFI::new()?;
    let runtime_wrapped = blocking_ctx.runtime();
    let ctx = blocking_ctx.ctx();

    // WAIT
    info!("Waiting for indexer to parse blocks");
    runtime_wrapped.block_on(async {
        tokio::time::sleep(std::time::Duration::from_millis(L2_TO_L1_TIMEOUT_MILLIS)).await;
    });

    let last_block_indexer = runtime_wrapped
        .block_on(ctx.indexer_client().get_last_finalized_block_id())
        .unwrap();

    info!("Last block on ind now is {last_block_indexer}");

    assert!(last_block_indexer > 1);

    // Getting wide batch to fit all blocks (from latest backwards)
    let mut block_batch = runtime_wrapped
        .block_on(ctx.indexer_client().get_blocks(None, 100))
        .unwrap();

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

#[test]
fn indexer_ffi_state_consistency() -> Result<()> {
    let mut blocking_ctx = BlockingTestContextFFI::new()?;
    let runtime_wrapped = blocking_ctx.runtime_clone();
    let ctx = blocking_ctx.ctx_mut();

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_public_account_id(ctx.existing_public_accounts()[0])),
        from_label: None,
        to: Some(format_public_account_id(ctx.existing_public_accounts()[1])),
        to_label: None,
        to_npk: None,
        to_vpk: None,
        amount: 100,
    });

    runtime_wrapped.block_on(wallet::cli::execute_subcommand(ctx.wallet_mut(), command))?;

    info!("Waiting for next block creation");
    runtime_wrapped.block_on(async {
        tokio::time::sleep(std::time::Duration::from_millis(
            TIME_TO_WAIT_FOR_BLOCK_SECONDS,
        ))
        .await;
    });

    info!("Checking correct balance move");
    let acc_1_balance =
        runtime_wrapped.block_on(sequencer_service_rpc::RpcClient::get_account_balance(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[0],
        ))?;
    let acc_2_balance =
        runtime_wrapped.block_on(sequencer_service_rpc::RpcClient::get_account_balance(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[1],
        ))?;

    info!("Balance of sender: {acc_1_balance:#?}");
    info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    let from: AccountId = ctx.existing_private_accounts()[0];
    let to: AccountId = ctx.existing_private_accounts()[1];

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: Some(format_private_account_id(from)),
        from_label: None,
        to: Some(format_private_account_id(to)),
        to_label: None,
        to_npk: None,
        to_vpk: None,
        amount: 100,
    });

    runtime_wrapped.block_on(wallet::cli::execute_subcommand(ctx.wallet_mut(), command))?;

    info!("Waiting for next block creation");
    runtime_wrapped.block_on(async {
        tokio::time::sleep(std::time::Duration::from_millis(
            TIME_TO_WAIT_FOR_BLOCK_SECONDS,
        ))
        .await;
    });

    let new_commitment1 = ctx
        .wallet()
        .get_private_account_commitment(from)
        .context("Failed to get private account commitment for sender")?;
    let commitment_check1 = runtime_wrapped.block_on(verify_commitment_is_in_state(
        new_commitment1,
        ctx.sequencer_client(),
    ));
    assert!(commitment_check1);

    let new_commitment2 = ctx
        .wallet()
        .get_private_account_commitment(to)
        .context("Failed to get private account commitment for receiver")?;
    let commitment_check2 = runtime_wrapped.block_on(verify_commitment_is_in_state(
        new_commitment2,
        ctx.sequencer_client(),
    ));
    assert!(commitment_check2);

    info!("Successfully transferred privately to owned account");

    // WAIT
    info!("Waiting for indexer to parse blocks");
    runtime_wrapped.block_on(async {
        tokio::time::sleep(std::time::Duration::from_millis(L2_TO_L1_TIMEOUT_MILLIS)).await;
    });

    let acc1_ind_state = runtime_wrapped.block_on(
        ctx.indexer_client()
            .get_account(ctx.existing_public_accounts()[0].into()),
    )?;
    let acc2_ind_state = runtime_wrapped.block_on(
        ctx.indexer_client()
            .get_account(ctx.existing_public_accounts()[1].into()),
    )?;

    info!("Checking correct state transition");
    let acc1_seq_state =
        runtime_wrapped.block_on(sequencer_service_rpc::RpcClient::get_account(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[0],
        ))?;
    let acc2_seq_state =
        runtime_wrapped.block_on(sequencer_service_rpc::RpcClient::get_account(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[1],
        ))?;

    assert_eq!(acc1_ind_state, acc1_seq_state.into());
    assert_eq!(acc2_ind_state, acc2_seq_state.into());

    // ToDo: Check private state transition

    Ok(())
}

#[test]
fn indexer_ffi_state_consistency_with_labels() -> Result<()> {
    let mut blocking_ctx = BlockingTestContextFFI::new()?;
    let runtime_wrapped = blocking_ctx.runtime_clone();
    let ctx = blocking_ctx.ctx_mut();

    // Assign labels to both accounts
    let from_label = "idx-sender-label".to_owned();
    let to_label_str = "idx-receiver-label".to_owned();

    let label_cmd = Command::Account(wallet::cli::account::AccountSubcommand::Label {
        account_id: Some(format_public_account_id(ctx.existing_public_accounts()[0])),
        account_label: None,
        label: from_label.clone(),
    });
    runtime_wrapped.block_on(wallet::cli::execute_subcommand(ctx.wallet_mut(), label_cmd))?;

    let label_cmd = Command::Account(wallet::cli::account::AccountSubcommand::Label {
        account_id: Some(format_public_account_id(ctx.existing_public_accounts()[1])),
        account_label: None,
        label: to_label_str.clone(),
    });
    runtime_wrapped.block_on(wallet::cli::execute_subcommand(ctx.wallet_mut(), label_cmd))?;

    // Send using labels instead of account IDs
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: None,
        from_label: Some(from_label),
        to: None,
        to_label: Some(to_label_str),
        to_npk: None,
        to_vpk: None,
        amount: 100,
    });

    runtime_wrapped.block_on(wallet::cli::execute_subcommand(ctx.wallet_mut(), command))?;

    info!("Waiting for next block creation");
    runtime_wrapped.block_on(async {
        tokio::time::sleep(std::time::Duration::from_millis(
            TIME_TO_WAIT_FOR_BLOCK_SECONDS,
        ))
        .await;
    });

    let acc_1_balance =
        runtime_wrapped.block_on(sequencer_service_rpc::RpcClient::get_account_balance(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[0],
        ))?;
    let acc_2_balance =
        runtime_wrapped.block_on(sequencer_service_rpc::RpcClient::get_account_balance(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[1],
        ))?;

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    info!("Waiting for indexer to parse blocks");
    runtime_wrapped.block_on(async {
        tokio::time::sleep(std::time::Duration::from_millis(L2_TO_L1_TIMEOUT_MILLIS)).await;
    });

    let acc1_ind_state = runtime_wrapped.block_on(
        ctx.indexer_client()
            .get_account(ctx.existing_public_accounts()[0].into()),
    )?;
    let acc1_seq_state =
        runtime_wrapped.block_on(sequencer_service_rpc::RpcClient::get_account(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[0],
        ))?;

    assert_eq!(acc1_ind_state, acc1_seq_state.into());

    info!("Indexer state is consistent after label-based transfer");

    Ok(())
}
