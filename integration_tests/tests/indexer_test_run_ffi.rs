#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;

#[path = "indexer_ffi_helpers/mod.rs"]
mod indexer_ffi_helpers;

#[test]
fn indexer_test_run_ffi() -> Result<()> {
    // `_ctx` keeps the bedrock/sequencer harness (and its runtime) alive for the
    // duration of the test; the indexer was started on that runtime.
    let (_ctx, indexer_ffi, _indexer_dir) = indexer_ffi_helpers::setup()?;

    // RUN OBSERVATION: poll until the indexer has finalized at least one block,
    // returning early instead of sleeping for the full timeout.
    let last_block_indexer_ffi = indexer_ffi_helpers::wait_for_indexer_ffi_block(&indexer_ffi, 1)?;

    log::info!("Last block on indexer FFI now is {last_block_indexer_ffi}");

    assert!(last_block_indexer_ffi > 0);

    Ok(())
}
