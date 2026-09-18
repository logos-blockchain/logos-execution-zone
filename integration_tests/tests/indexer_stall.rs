#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use std::time::Duration;

use anyhow::{Context as _, Result};
use indexer_service_protocol::IndexerSyncState;
use indexer_service_rpc::RpcClient as _;
use integration_tests::{TestContext, wait_for_indexer_to_catch_up};

const CAUGHT_UP_STATUS_TIMEOUT: Duration = Duration::from_secs(60);

/// Test that the indexer status RPC reports caught-up with no stall after a clean run.
///
/// The sequencer keeps producing blocks while we assert, so the status is polled until a
/// `CaughtUp` snapshot is observed and the indexed tip is checked as a lower bound.
///
/// TODO: Integration-level park testing (publishing a bad block to force a stall) is a follow-up
/// needing fault injection support in the test harness.
#[tokio::test]
async fn indexer_status_rpc_reports_caught_up_with_no_stall() -> Result<()> {
    let ctx = TestContext::new().await?;

    let indexer_tip = wait_for_indexer_to_catch_up(&ctx).await?;

    let status = tokio::time::timeout(CAUGHT_UP_STATUS_TIMEOUT, async {
        loop {
            let status = ctx.indexer_client().get_status().await?;
            if status.state == IndexerSyncState::CaughtUp {
                return anyhow::Ok(status);
            }
            log::info!("Waiting for caught-up indexer status, got {status:?}");
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .context("Timed out waiting for indexer status to report caught-up")??;

    assert!(
        status.stall_reason.is_none(),
        "indexer should have no stall reason after a clean run, got {status:?}"
    );
    // test for >= here because the sequencer keeps producing blocks while we assert,
    // so the indexed tip may be ahead of the tip we observed when we waited for caught-up.
    assert!(
        status.indexed_block_id >= Some(indexer_tip),
        "status indexed_block_id should be at least the caught-up tip {indexer_tip}, got {status:?}"
    );

    Ok(())
}
