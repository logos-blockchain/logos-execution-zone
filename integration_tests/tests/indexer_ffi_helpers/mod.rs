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
        query::LastBlockIdResult,
        types::{FfiAccountId, FfiOption, FfiVec, account::FfiAccount, block::FfiBlock},
    },
};
use integration_tests::BlockingTestContext;
use tempfile::TempDir;
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};

unsafe extern "C" {
    pub unsafe fn query_last_block(indexer: *const IndexerServiceFFI) -> LastBlockIdResult;

    pub unsafe fn query_block_vec(
        indexer: *const IndexerServiceFFI,
        before: FfiOption<u64>,
        limit: u64,
    ) -> PointerResult<FfiVec<FfiBlock>, OperationStatus>;

    pub unsafe fn query_account(
        indexer: *const IndexerServiceFFI,
        account_id: FfiAccountId,
    ) -> PointerResult<FfiAccount, OperationStatus>;

    pub unsafe fn start_indexer(
        runtime: *const Runtime,
        config_path: *const c_char,
        storage_dir: *const c_char,
    ) -> InitializedIndexerServiceFFIResult;
}

pub fn setup_indexer_ffi(bedrock_addr: SocketAddr) -> Result<(IndexerServiceFFI, TempDir)> {
    let temp_indexer_dir =
        tempfile::tempdir().context("Failed to create temp dir for indexer home")?;

    log::debug!(
        "Using temp indexer home at {}",
        temp_indexer_dir.path().display()
    );

    let indexer_config = integration_tests::config::indexer_config(
        bedrock_addr,
        integration_tests::config::bedrock_channel_id(),
        None,
    )
    .context("Failed to create Indexer config")?;

    let config_json = serde_json::to_vec(&indexer_config)?;
    let config_path = temp_indexer_dir.path().join("indexer_config.json");
    let mut file = File::create(config_path.as_path())?;
    file.write_all(&config_json)?;
    file.flush()?;

    let config_path_c = CString::new(config_path.to_str().unwrap())?;
    let storage_dir_c = CString::new(temp_indexer_dir.path().to_str().unwrap())?;
    let res =
        // SAFETY: null runtime → the FFI creates and owns its own tokio runtime,
        // so there is no external runtime whose address we must keep stable. The
        // temp dir is the indexer's storage location.
        unsafe { start_indexer(std::ptr::null(), config_path_c.as_ptr(), storage_dir_c.as_ptr()) };

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
    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default()).disable_indexer(),
        )
        .build_blocking()?;

    // Don't borrow `ctx.runtime()`: `ctx` (and its by-value tokio runtime) is
    // moved into the returned tuple, which would leave any pointer into it
    // dangling. Pass a null runtime so the FFI owns its own — the same path the
    // production module uses.
    let (indexer_ffi, indexer_dir) = setup_indexer_ffi(ctx.ctx().bedrock_addr())?;
    Ok((ctx, indexer_ffi, indexer_dir))
}

/// Poll the indexer FFI until its last finalized block id reaches `min_block_id`
/// or until [`integration_tests::L2_TO_L1_TIMEOUT`] elapses.
///
/// This avoids blindly sleeping for the full timeout: the indexer typically
/// catches up in a fraction of that time, so we return as soon as it does and
/// only use the timeout as a ceiling. Returns the last observed block id.
pub fn wait_for_indexer_ffi_block(indexer: &IndexerServiceFFI, min_block_id: u64) -> Result<u64> {
    let start = std::time::Instant::now();
    loop {
        // SAFETY: `indexer` is a valid reference for the duration of the call.
        let res = unsafe { query_last_block(std::ptr::from_ref(indexer)) };
        if res.error.is_ok() && res.is_some && res.block_id >= min_block_id {
            return Ok(res.block_id);
        }
        if start.elapsed() >= integration_tests::L2_TO_L1_TIMEOUT {
            anyhow::bail!(
                "Indexer FFI did not reach block {min_block_id} within {:?}. Last observed block id: {}",
                integration_tests::L2_TO_L1_TIMEOUT,
                res.block_id
            );
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}
