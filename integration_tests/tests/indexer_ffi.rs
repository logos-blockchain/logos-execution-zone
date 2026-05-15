#![expect(
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    clippy::undocumented_unsafe_blocks,
    reason = "We don't care about these in tests"
)]

use std::{
    ffi::{CString, c_char},
    fs::File,
    io::Write as _,
    net::SocketAddr,
};

use anyhow::{Context as _, Result};
use indexer_ffi::{
    IndexerServiceFFI, OperationStatus, Runtime,
    api::{
        PointerResult,
        lifecycle::InitializedIndexerServiceFFIResult,
        types::{FfiAccountId, FfiOption, FfiVec, account::FfiAccount, block::FfiBlock},
    },
};
use integration_tests::{
    BlockingTestContext, TIME_TO_WAIT_FOR_BLOCK_SECONDS, TestContext, private_mention,
    public_mention, verify_commitment_is_in_state,
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
    unsafe fn query_last_block(
        runtime: *const Runtime,
        indexer: *const IndexerServiceFFI,
    ) -> PointerResult<u64, OperationStatus>;

    unsafe fn query_block_vec(
        runtime: *const Runtime,
        indexer: *const IndexerServiceFFI,
        before: FfiOption<u64>,
        limit: u64,
    ) -> PointerResult<FfiVec<FfiBlock>, OperationStatus>;

    unsafe fn query_account(
        runtime: *const Runtime,
        indexer: *const IndexerServiceFFI,
        account_id: FfiAccountId,
    ) -> PointerResult<FfiAccount, OperationStatus>;

    unsafe fn start_indexer(
        runtime: *const Runtime,
        config_path: *const c_char,
        port: u16,
    ) -> InitializedIndexerServiceFFIResult;
}

fn setup_indexer_ffi(
    runtime: &Runtime,
    bedrock_addr: SocketAddr,
) -> Result<(IndexerServiceFFI, TempDir)> {
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
            unsafe { start_indexer(std::ptr::from_ref(runtime), CString::new(config_path.to_str().unwrap())?.as_ptr(), 0) };

    if res.error.is_error() {
        anyhow::bail!("Indexer FFI error {:?}", res.error);
    }

    Ok((
        // SAFETY: lib function ensures validity of value.
        unsafe { std::ptr::read(res.value) },
        temp_indexer_dir,
    ))
}

/// Prepare setup for tests.
fn setup() -> Result<(BlockingTestContext, IndexerServiceFFI, TempDir)> {
    let ctx = TestContext::builder().disable_indexer().build_blocking()?;
    // Safety: ctx runtime is valid for the lifetime of the returned Runtime
    let runtime = unsafe { Runtime::from_borrowed(ctx.runtime()) };
    let (indexer_ffi, indexer_dir) = setup_indexer_ffi(&runtime, ctx.ctx().bedrock_addr())?;

    Ok((ctx, indexer_ffi, indexer_dir))
}

#[test]
fn indexer_test_run_ffi() -> Result<()> {
    let (ctx, indexer_ffi, _indexer_dir) = setup()?;

    // RUN OBSERVATION
    std::thread::sleep(std::time::Duration::from_millis(L2_TO_L1_TIMEOUT_MILLIS));

    // Safety: ctx runtime is valid for the lifetime of the returned Runtime
    let runtime = unsafe { Runtime::from_borrowed(ctx.runtime()) };
    let last_block_indexer_ffi_res =
        unsafe { query_last_block(&raw const runtime, &raw const indexer_ffi) };

    assert!(last_block_indexer_ffi_res.error.is_ok());

    let last_block_indexer_ffi = unsafe { *last_block_indexer_ffi_res.value };

    info!("Last block on indexer FFI now is {last_block_indexer_ffi}");

    assert!(last_block_indexer_ffi > 0);

    Ok(())
}

#[test]
fn indexer_ffi_block_batching() -> Result<()> {
    let (ctx, indexer_ffi, _indexer_dir) = setup()?;

    // WAIT
    info!("Waiting for indexer to parse blocks");
    std::thread::sleep(std::time::Duration::from_millis(L2_TO_L1_TIMEOUT_MILLIS));

    // Safety: ctx runtime is valid for the lifetime of the returned Runtime
    let runtime = unsafe { Runtime::from_borrowed(ctx.runtime()) };
    let last_block_indexer_ffi_res =
        unsafe { query_last_block(&raw const runtime, &raw const indexer_ffi) };

    assert!(last_block_indexer_ffi_res.error.is_ok());

    let last_block_indexer = unsafe { *last_block_indexer_ffi_res.value };

    info!("Last block on indexer FFI now is {last_block_indexer}");

    assert!(last_block_indexer > 0);

    let before_ffi = FfiOption::<u64>::from_none();
    let limit = 100;

    let block_batch_ffi_res = unsafe {
        query_block_vec(
            &raw const runtime,
            &raw const indexer_ffi,
            before_ffi,
            limit,
        )
    };

    assert!(block_batch_ffi_res.error.is_ok());

    let block_batch = unsafe { &*block_batch_ffi_res.value };

    let mut last_block_prev_hash = unsafe { block_batch.get(0) }.header.prev_block_hash.data;

    for i in 1..block_batch.len {
        let block = unsafe { block_batch.get(i) };

        assert_eq!(last_block_prev_hash, block.header.hash.data);

        info!("Block {} chain-consistent", block.header.block_id);

        last_block_prev_hash = block.header.prev_block_hash.data;
    }

    Ok(())
}

#[test]
fn indexer_ffi_state_consistency() -> Result<()> {
    let (mut ctx, indexer_ffi, _indexer_dir) = setup()?;

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

    // Safety: ctx runtime is valid for the lifetime of the returned Runtime
    let runtime = unsafe { Runtime::from_borrowed(ctx.runtime()) };
    let acc1_ind_state_ffi = unsafe {
        query_account(
            &raw const runtime,
            &raw const indexer_ffi,
            (&ctx.ctx().existing_public_accounts()[0]).into(),
        )
    };

    assert!(acc1_ind_state_ffi.error.is_ok());

    let acc1_ind_state_pre = unsafe { &*acc1_ind_state_ffi.value };
    let acc1_ind_state: indexer_service_protocol::Account = acc1_ind_state_pre.into();

    let acc2_ind_state_ffi = unsafe {
        query_account(
            &raw const runtime,
            &raw const indexer_ffi,
            (&ctx.ctx().existing_public_accounts()[1]).into(),
        )
    };

    assert!(acc2_ind_state_ffi.error.is_ok());

    let acc2_ind_state_pre = unsafe { &*acc2_ind_state_ffi.value };
    let acc2_ind_state: indexer_service_protocol::Account = acc2_ind_state_pre.into();

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
    let (mut ctx, indexer_ffi, _indexer_dir) = setup()?;

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

    // Safety: ctx runtime is valid for the lifetime of the returned Runtime
    let runtime = unsafe { Runtime::from_borrowed(ctx.runtime()) };
    let acc1_ind_state_ffi = unsafe {
        query_account(
            &raw const runtime,
            &raw const indexer_ffi,
            (&ctx.ctx().existing_public_accounts()[0]).into(),
        )
    };

    assert!(acc1_ind_state_ffi.error.is_ok());

    let acc1_ind_state_pre = unsafe { &*acc1_ind_state_ffi.value };
    let acc1_ind_state: indexer_service_protocol::Account = acc1_ind_state_pre.into();

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
