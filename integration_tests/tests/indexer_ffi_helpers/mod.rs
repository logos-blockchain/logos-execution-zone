#![allow(dead_code, reason = "helper module used only by FFI test binaries")]

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
use integration_tests::{BlockingTestContext, TestContext};
use tempfile::TempDir;

unsafe extern "C" {
    pub unsafe fn query_last_block(
        runtime: *const Runtime,
        indexer: *const IndexerServiceFFI,
    ) -> PointerResult<u64, OperationStatus>;

    pub unsafe fn query_block_vec(
        runtime: *const Runtime,
        indexer: *const IndexerServiceFFI,
        before: FfiOption<u64>,
        limit: u64,
    ) -> PointerResult<FfiVec<FfiBlock>, OperationStatus>;

    pub unsafe fn query_account(
        runtime: *const Runtime,
        indexer: *const IndexerServiceFFI,
        account_id: FfiAccountId,
    ) -> PointerResult<FfiAccount, OperationStatus>;

    pub unsafe fn start_indexer(
        runtime: *const Runtime,
        config_path: *const c_char,
        port: u16,
    ) -> InitializedIndexerServiceFFIResult;
}

pub fn setup_indexer_ffi(
    runtime: &Runtime,
    bedrock_addr: SocketAddr,
) -> Result<(IndexerServiceFFI, TempDir)> {
    let temp_indexer_dir =
        tempfile::tempdir().context("Failed to create temp dir for indexer home")?;

    log::debug!(
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

pub fn setup() -> Result<(BlockingTestContext, IndexerServiceFFI, TempDir)> {
    let ctx = TestContext::builder().disable_indexer().build_blocking()?;
    // Safety: ctx runtime is valid for the lifetime of the returned Runtime
    let runtime = unsafe { Runtime::from_borrowed(ctx.runtime()) };
    let (indexer_ffi, indexer_dir) = setup_indexer_ffi(&runtime, ctx.ctx().bedrock_addr())?;
    Ok((ctx, indexer_ffi, indexer_dir))
}
