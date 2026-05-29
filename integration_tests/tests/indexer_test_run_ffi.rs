#![expect(
    clippy::tests_outside_test_module,
    clippy::undocumented_unsafe_blocks,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use indexer_ffi::Runtime;
use integration_tests::L2_TO_L1_TIMEOUT;
use log::info;

#[path = "indexer_ffi_helpers/mod.rs"]
mod indexer_ffi_helpers;

#[test]
fn indexer_test_run_ffi() -> Result<()> {
    let (ctx, indexer_ffi, _indexer_dir) = indexer_ffi_helpers::setup()?;

    // RUN OBSERVATION
    std::thread::sleep(L2_TO_L1_TIMEOUT);

    // Safety: ctx runtime is valid for the lifetime of the returned Runtime
    let runtime = unsafe { Runtime::from_borrowed(ctx.runtime()) };
    let last_block_indexer_ffi_res = unsafe {
        indexer_ffi_helpers::query_last_block(&raw const runtime, &raw const indexer_ffi)
    };

    assert!(last_block_indexer_ffi_res.error.is_ok());

    let last_block_indexer_ffi = unsafe { *last_block_indexer_ffi_res.value };

    info!("Last block on indexer FFI now is {last_block_indexer_ffi}");

    assert!(last_block_indexer_ffi > 0);

    Ok(())
}
