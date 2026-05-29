#![expect(
    clippy::tests_outside_test_module,
    clippy::undocumented_unsafe_blocks,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use indexer_ffi::{Runtime, api::types::FfiOption};
use integration_tests::L2_TO_L1_TIMEOUT;
use log::info;

#[path = "indexer_ffi_helpers/mod.rs"]
mod indexer_ffi_helpers;

#[test]
fn indexer_ffi_block_batching() -> Result<()> {
    let (ctx, indexer_ffi, _indexer_dir) = indexer_ffi_helpers::setup()?;

    // WAIT
    info!("Waiting for indexer to parse blocks");
    std::thread::sleep(L2_TO_L1_TIMEOUT);

    // Safety: ctx runtime is valid for the lifetime of the returned Runtime
    let runtime = unsafe { Runtime::from_borrowed(ctx.runtime()) };
    let last_block_indexer_ffi_res = unsafe {
        indexer_ffi_helpers::query_last_block(&raw const runtime, &raw const indexer_ffi)
    };

    assert!(last_block_indexer_ffi_res.error.is_ok());

    let last_block_indexer = unsafe { *last_block_indexer_ffi_res.value };

    info!("Last block on indexer FFI now is {last_block_indexer}");

    assert!(last_block_indexer > 0);

    let before_ffi = FfiOption::<u64>::from_none();
    let limit = 100;

    let block_batch_ffi_res = unsafe {
        indexer_ffi_helpers::query_block_vec(
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
