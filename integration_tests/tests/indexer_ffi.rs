#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::{
    ffi::{CString, c_char},
    fs::File,
    io::Write as _,
    net::SocketAddr,
};

use anyhow::{Context as _, Result};
use indexer_ffi::{IndexerServiceFFI, api::lifecycle::InitializedIndexerServiceFFIResult};
use indexer_service_rpc::RpcClient as _;
use integration_tests::{
    BlockingTestContext, TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, private_mention,
    public_mention, setup::setup_bedrock_node, verify_commitment_is_in_state,
};
use log::{debug, info};
use nssa::AccountId;
use tempfile::TempDir;
use wallet::{
    account::Label,
    cli::{Command, programs::native_token_transfer::AuthTransferSubcommand},
};

/// Maximum time to wait for the indexer to catch up to the sequencer.
const L2_TO_L1_TIMEOUT_MILLIS: u64 = 180_000;

unsafe extern "C" {
    fn start_indexer(config_path: *const c_char, port: u16) -> InitializedIndexerServiceFFIResult;
}

fn setup_indexer_ffi(bedrock_addr: SocketAddr) -> Result<(IndexerServiceFFI, TempDir)> {
    let temp_indexer_dir =
        tempfile::tempdir().context("Failed to create temp dir for indexer home")?;

    debug!(
        "Using temp indexer home at {}",
        temp_indexer_dir.path().display()
    );

    let indexer_config =
        integration_tests::config::indexer_config(bedrock_addr, temp_indexer_dir.path().to_owned())
            .context("Failed to create Indexer config")?;

    let config_json = serde_json::to_vec(&indexer_config)?;
    let config_path = temp_indexer_dir.path().join("indexer_config.json");
    let mut file = File::create(config_path.as_path())?;
    file.write_all(&config_json)?;
    file.flush()?;

    let res =
            // SAFETY: lib function ensures validity of value.
            unsafe { start_indexer(CString::new(config_path.to_str().unwrap())?.as_ptr(), 0) };

    if res.error.is_error() {
        anyhow::bail!("Indexer FFI error {:?}", res.error);
    }

    Ok((
        // SAFETY: lib function ensures validity of value.
        unsafe { std::ptr::read(res.value) },
        temp_indexer_dir,
    ))
}

/// Setup [`BlockingTestContext`] with Indexer running through FFI.
fn setup_blocking_test_context() -> Result<(BlockingTestContext, TempDir)> {
    let (bedrock_compose, bedrock_addr) =
        tokio::runtime::Runtime::new()?.block_on(setup_bedrock_node())?;

    let (indexer_ffi, indexer_dir) = setup_indexer_ffi(bedrock_addr)?;

    // SAFETY: Pointer returned from FFI is valid
    let (handle, runtime) = unsafe { indexer_ffi.into_parts() };

    let ctx = TestContext::builder()
        .with_bedrock(bedrock_compose, bedrock_addr)
        .with_indexer(*handle)
        .with_runtime(*runtime)
        .build_blocking()?;

    Ok((ctx, indexer_dir))
}

#[test]
fn indexer_test_run_ffi() -> Result<()> {
    let (ctx, _indexer_dir) = setup_blocking_test_context()?;

    // RUN OBSERVATION
    std::thread::sleep(std::time::Duration::from_millis(L2_TO_L1_TIMEOUT_MILLIS));

    let last_block_indexer = ctx
        .block_on(|ctx| ctx.indexer_client().get_last_finalized_block_id())?
        .unwrap();

    info!("Last block on ind now is {last_block_indexer}");

    assert!(last_block_indexer > 1);

    Ok(())
}

#[test]
fn indexer_ffi_block_batching() -> Result<()> {
    let (ctx, _indexer_dir) = setup_blocking_test_context()?;

    // WAIT
    info!("Waiting for indexer to parse blocks");
    std::thread::sleep(std::time::Duration::from_millis(L2_TO_L1_TIMEOUT_MILLIS));

    let last_block_indexer = ctx
        .block_on(|ctx| ctx.indexer_client().get_last_finalized_block_id())?
        .unwrap();

    info!("Last block on ind now is {last_block_indexer}");

    assert!(last_block_indexer > 1);

    // Getting wide batch to fit all blocks (from latest backwards)
    let mut block_batch = ctx.block_on(|ctx| ctx.indexer_client().get_blocks(None, 100))?;

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
    let (mut ctx, _indexer_dir) = setup_blocking_test_context()?;

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: public_mention(ctx.ctx().existing_public_accounts()[0]),
        to: Some(public_mention(ctx.ctx().existing_public_accounts()[1])),
        to_npk: None,
        to_vpk: None,
        amount: 100,
        to_identifier: Some(0),
    });

    ctx.block_on_mut(|ctx| wallet::cli::execute_subcommand(ctx.wallet_mut(), command))?;

    info!("Waiting for next block creation");
    std::thread::sleep(std::time::Duration::from_secs(
        TIME_TO_WAIT_FOR_BLOCK_SECONDS,
    ));

    info!("Checking correct balance move");
    let acc_1_balance = ctx.block_on(|ctx| {
        sequencer_service_rpc::RpcClient::get_account_balance(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[0],
        )
    })?;
    let acc_2_balance = ctx.block_on(|ctx| {
        sequencer_service_rpc::RpcClient::get_account_balance(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[1],
        )
    })?;

    info!("Balance of sender: {acc_1_balance:#?}");
    info!("Balance of receiver: {acc_2_balance:#?}");

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    let from: AccountId = ctx.ctx().existing_private_accounts()[0];
    let to: AccountId = ctx.ctx().existing_private_accounts()[1];

    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: private_mention(from),
        to: Some(private_mention(to)),
        to_npk: None,
        to_vpk: None,
        amount: 100,
        to_identifier: Some(0),
    });

    ctx.block_on_mut(|ctx| wallet::cli::execute_subcommand(ctx.wallet_mut(), command))?;

    info!("Waiting for next block creation");
    std::thread::sleep(std::time::Duration::from_secs(
        TIME_TO_WAIT_FOR_BLOCK_SECONDS,
    ));

    let new_commitment1 = ctx
        .ctx()
        .wallet()
        .get_private_account_commitment(from)
        .context("Failed to get private account commitment for sender")?;
    let commitment_check1 =
        ctx.block_on(|ctx| verify_commitment_is_in_state(new_commitment1, ctx.sequencer_client()));
    assert!(commitment_check1);

    let new_commitment2 = ctx
        .ctx()
        .wallet()
        .get_private_account_commitment(to)
        .context("Failed to get private account commitment for receiver")?;
    let commitment_check2 =
        ctx.block_on(|ctx| verify_commitment_is_in_state(new_commitment2, ctx.sequencer_client()));
    assert!(commitment_check2);

    info!("Successfully transferred privately to owned account");

    // WAIT
    info!("Waiting for indexer to parse blocks");
    std::thread::sleep(std::time::Duration::from_millis(L2_TO_L1_TIMEOUT_MILLIS));

    let acc1_ind_state = ctx.block_on(|ctx| {
        ctx.indexer_client()
            .get_account(ctx.existing_public_accounts()[0].into())
    })?;
    let acc2_ind_state = ctx.block_on(|ctx| {
        ctx.indexer_client()
            .get_account(ctx.existing_public_accounts()[1].into())
    })?;

    info!("Checking correct state transition");
    let acc1_seq_state = ctx.block_on(|ctx| {
        sequencer_service_rpc::RpcClient::get_account(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[0],
        )
    })?;
    let acc2_seq_state = ctx.block_on(|ctx| {
        sequencer_service_rpc::RpcClient::get_account(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[1],
        )
    })?;

    assert_eq!(acc1_ind_state, acc1_seq_state.into());
    assert_eq!(acc2_ind_state, acc2_seq_state.into());

    // ToDo: Check private state transition

    Ok(())
}

#[test]
fn indexer_ffi_state_consistency_with_labels() -> Result<()> {
    let (mut ctx, _indexer_dir) = setup_blocking_test_context()?;

    // Assign labels to both accounts
    let from_label = Label::new("idx-sender-label");
    let to_label = Label::new("idx-receiver-label");

    let label_cmd = Command::Account(wallet::cli::account::AccountSubcommand::Label {
        account_id: public_mention(ctx.ctx().existing_public_accounts()[0]),
        label: from_label.clone(),
    });
    ctx.block_on_mut(|ctx| wallet::cli::execute_subcommand(ctx.wallet_mut(), label_cmd))?;

    let label_cmd = Command::Account(wallet::cli::account::AccountSubcommand::Label {
        account_id: public_mention(ctx.ctx().existing_public_accounts()[1]),
        label: to_label.clone(),
    });
    ctx.block_on_mut(|ctx| wallet::cli::execute_subcommand(ctx.wallet_mut(), label_cmd))?;

    // Send using labels instead of account IDs
    let command = Command::AuthTransfer(AuthTransferSubcommand::Send {
        from: from_label.into(),
        to: Some(to_label.into()),
        to_npk: None,
        to_vpk: None,
        amount: 100,
        to_identifier: Some(0),
    });

    ctx.block_on_mut(|ctx| wallet::cli::execute_subcommand(ctx.wallet_mut(), command))?;

    info!("Waiting for next block creation");
    std::thread::sleep(std::time::Duration::from_secs(
        TIME_TO_WAIT_FOR_BLOCK_SECONDS,
    ));

    let acc_1_balance = ctx.block_on(|ctx| {
        sequencer_service_rpc::RpcClient::get_account_balance(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[0],
        )
    })?;
    let acc_2_balance = ctx.block_on(|ctx| {
        sequencer_service_rpc::RpcClient::get_account_balance(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[1],
        )
    })?;

    assert_eq!(acc_1_balance, 9900);
    assert_eq!(acc_2_balance, 20100);

    info!("Waiting for indexer to parse blocks");
    std::thread::sleep(std::time::Duration::from_millis(L2_TO_L1_TIMEOUT_MILLIS));

    let acc1_ind_state = ctx.block_on(|ctx| {
        ctx.indexer_client()
            .get_account(ctx.existing_public_accounts()[0].into())
    })?;
    let acc1_seq_state = ctx.block_on(|ctx| {
        sequencer_service_rpc::RpcClient::get_account(
            ctx.sequencer_client(),
            ctx.existing_public_accounts()[0],
        )
    })?;

    assert_eq!(acc1_ind_state, acc1_seq_state.into());

    info!("Indexer state is consistent after label-based transfer");

    Ok(())
}
