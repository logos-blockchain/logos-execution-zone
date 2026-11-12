#![expect(
    clippy::tests_outside_test_module,
    reason = "We don't care about these in tests"
)]

use anyhow::Result;
use integration_tests::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder,
    config::{MultiNodeTestContextConfig, SequencerPartialConfig},
    wait_for_indexer_to_catch_up,
};

#[tokio::test]
async fn indexer_test_run() -> Result<()> {
    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig::default())
                .with_sequencer_partial_config(SequencerPartialConfig {
                    // Covers the storage price doubling at the devnet's first epoch rotations.
                    priority_fee_percent: 150,
                    ..SequencerPartialConfig::default()
                }),
        )
        .build()
        .await?;

    let last_block_indexer = wait_for_indexer_to_catch_up(&ctx).await?;

    let last_block_seq =
        sequencer_service_rpc::RpcClient::get_last_block_id(ctx.sequencer_client()).await?;

    log::info!("Last block on seq now is {last_block_seq}");
    log::info!("Last block on ind now is {last_block_indexer}");

    assert!(last_block_indexer > 0);

    Ok(())
}
