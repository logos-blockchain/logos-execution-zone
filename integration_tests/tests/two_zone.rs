#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! Two zones (sequencer + indexer each, on separate channels) sharing one
//! Bedrock node, each producing and finalizing blocks independently.

use std::time::Duration;

use anyhow::{Context as _, Result};
use indexer_service_rpc::RpcClient as _;
use integration_tests::{
    config::{self, SequencerPartialConfig},
    indexer_client::IndexerClient,
};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use tokio::test;

const ZONE_LIVE_TIMEOUT: Duration = Duration::from_secs(360);

// Genesis is block 1, so reaching 2 means a block was produced past it.
const MIN_BLOCK_ID: u64 = 2;

#[test]
async fn two_zones_share_one_bedrock_and_both_advance() -> Result<()> {
    let channel_a = config::bedrock_channel_id();
    let channel_b = config::bedrock_channel_id_b();
    let partial = SequencerPartialConfig::default();

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 1,
                bedrock_channel: channel_a,
            })
            .disable_wallet()
            .with_sequencer_partial_config(partial)
            .with_genesis(vec![]),
        )
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 1,
                bedrock_channel: channel_b,
            })
            .disable_wallet()
            .with_sequencer_partial_config(partial)
            .with_genesis(vec![]),
        )
        .build()
        .await?;

    let ind_client_a = ctx.indexer_client_zone(channel_a).unwrap();
    let ind_client_b = ctx.indexer_client_zone(channel_b).unwrap();

    let seq_client_a = &ctx
        .zone_default_sequencer_component(channel_a)
        .sequencer_client;
    let seq_client_b = &ctx
        .zone_default_sequencer_component(channel_b)
        .sequencer_client;

    let (height_a, height_b) = tokio::try_join!(
        wait_until_zone_live("A", seq_client_a, ind_client_a),
        wait_until_zone_live("B", seq_client_b, ind_client_b),
    )?;

    assert!(
        height_a >= MIN_BLOCK_ID,
        "Zone A indexer only reached block {height_a}, expected >= {MIN_BLOCK_ID}"
    );
    assert!(
        height_b >= MIN_BLOCK_ID,
        "Zone B indexer only reached block {height_b}, expected >= {MIN_BLOCK_ID}"
    );

    Ok(())
}

/// Wait for the sequencer to produce past genesis and the indexer to finalize up
/// to it. Returns the indexer's finalized block id.
async fn wait_until_zone_live(
    label: &str,
    sequencer_client: &SequencerClient,
    indexer_client: &IndexerClient,
) -> Result<u64> {
    let wait = async {
        loop {
            if sequencer_client.get_last_block_id().await? >= MIN_BLOCK_ID {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let target = sequencer_client.get_last_block_id().await?;
        loop {
            let finalized = indexer_client
                .get_last_finalized_block_id()
                .await?
                .unwrap_or(0);
            if finalized >= target {
                log::info!(
                    "Zone {label} live: sequencer at {target}, indexer finalized {finalized}"
                );
                return Ok::<u64, anyhow::Error>(finalized);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };

    tokio::time::timeout(ZONE_LIVE_TIMEOUT, wait)
        .await
        .with_context(|| format!("Zone {label} did not become live within {ZONE_LIVE_TIMEOUT:?}"))?
}
