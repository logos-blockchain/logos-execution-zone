#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use integration_tests::{TestContext, wait_for_indexer_to_catch_up};
use log::info;

#[tokio::test]
async fn indexer_test_run() -> Result<()> {
    let ctx = TestContext::new().await?;

    let last_block_indexer = wait_for_indexer_to_catch_up(&ctx).await?;

    let last_block_seq =
        sequencer_service_rpc::RpcClient::get_last_block_id(ctx.sequencer_client()).await?;

    info!("Last block on seq now is {last_block_seq}");
    info!("Last block on ind now is {last_block_indexer}");

    assert!(last_block_indexer > 0);

    Ok(())
}
