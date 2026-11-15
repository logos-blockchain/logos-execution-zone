#![expect(
    clippy::tests_outside_test_module,
    clippy::undocumented_unsafe_blocks,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use indexer_ffi::api::types::FfiOption;

#[path = "indexer_ffi_helpers/mod.rs"]
mod indexer_ffi_helpers;

#[test]
fn indexer_ffi_block_batching() -> Result<()> {
    // `_ctx` keeps the bedrock/sequencer harness (and its runtime) alive for the
    // duration of the test; the indexer was started on that runtime.
    let (_ctx, indexer_ffi, _indexer_dir) = indexer_ffi_helpers::setup()?;

    // WAIT: poll until the indexer has finalized at least two blocks (so the
    // chain-consistency check below verifies at least one block link), returning
    // early instead of sleeping for the full timeout.
    tracing::info!("Waiting for indexer to parse blocks");
    let last_block_indexer = indexer_ffi_helpers::wait_for_indexer_ffi_block(&indexer_ffi, 2)?;

    tracing::info!(last_block_indexer, "Indexer FFI last block");

    assert!(last_block_indexer > 0);

    let before_ffi = FfiOption::<u64>::from_none();
    let limit = 100;

    let block_batch_ffi_res =
        unsafe { indexer_ffi_helpers::query_block_vec(&raw const indexer_ffi, before_ffi, limit) };

    assert!(block_batch_ffi_res.error.is_ok());

    let block_batch = unsafe { &*block_batch_ffi_res.value };

    let mut last_block_prev_hash = unsafe { block_batch.get(0) }.header.prev_block_hash.data;

    for i in 1..block_batch.len {
        let block = unsafe { block_batch.get(i) };

        assert_eq!(last_block_prev_hash, block.header.hash.data);

        tracing::info!(block_id = block.header.block_id, "Block chain-consistent");

        last_block_prev_hash = block.header.prev_block_hash.data;
    }

    Ok(())
}
