#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use indexer_service_rpc::RpcClient as _;
use integration_tests::{TestContext, wait_for_indexer_to_catch_up};
use log::info;

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
