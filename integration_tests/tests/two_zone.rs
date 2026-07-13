#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! Two zones (sequencer + indexer each, on separate channels) sharing one
//! Bedrock node, each producing and finalizing blocks independently.

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context as _, Result};
use indexer_service_rpc::RpcClient as _;
use integration_tests::{
    config::{self, SequencerPartialConfig},
    indexer_client::IndexerClient,
    setup::{setup_bedrock_node, setup_indexer, setup_sequencer},
};
use sequencer_service_rpc::{RpcClient as _, SequencerClientBuilder};
use tokio::test;

const ZONE_LIVE_TIMEOUT: Duration = Duration::from_secs(360);

// Genesis is block 1, so reaching 2 means a block was produced past it.
const MIN_BLOCK_ID: u64 = 2;

#[test]
async fn two_zones_share_one_bedrock_and_both_advance() -> Result<()> {
    // Declared first so it outlives both zones (drops run in reverse order).
    let (_bedrock, bedrock_addr) = setup_bedrock_node()
        .await
        .context("Failed to set up shared Bedrock node")?;

    let partial = SequencerPartialConfig::default();
    let channel_a = config::bedrock_channel_id();
    let channel_b = config::bedrock_channel_id_b();

    // Empty genesis is enough: the clock transaction drives block production.
    let (seq_a, _seq_a_home) = setup_sequencer(partial, bedrock_addr, vec![], channel_a, None)
        .await
        .context("Failed to set up zone A sequencer")?;
    let (idx_a, _idx_a_home) = setup_indexer(bedrock_addr, channel_a, None)
        .await
        .context("Failed to set up zone A indexer")?;
    let (seq_b, _seq_b_home) = setup_sequencer(partial, bedrock_addr, vec![], channel_b, None)
        .await
        .context("Failed to set up zone B sequencer")?;
    let (idx_b, _idx_b_home) = setup_indexer(bedrock_addr, channel_b, None)
        .await
        .context("Failed to set up zone B indexer")?;

    let (height_a, height_b) = tokio::try_join!(
        wait_until_zone_live("A", seq_a.addr(), idx_a.addr()),
        wait_until_zone_live("B", seq_b.addr(), idx_b.addr()),
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
    sequencer_addr: SocketAddr,
    indexer_addr: SocketAddr,
) -> Result<u64> {
    let sequencer_url = config::addr_to_url(config::UrlProtocol::Http, sequencer_addr)
        .context("Failed to build sequencer URL")?;
    let sequencer = SequencerClientBuilder::default()
        .build(sequencer_url)
        .context("Failed to build sequencer client")?;

    let indexer_url = config::addr_to_url(config::UrlProtocol::Ws, indexer_addr)
        .context("Failed to build indexer URL")?;
    let indexer = IndexerClient::new(&indexer_url)
        .await
        .context("Failed to build indexer client")?;

    let wait = async {
        loop {
            if sequencer.get_last_block_id().await? >= MIN_BLOCK_ID {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let target = sequencer.get_last_block_id().await?;
        loop {
            let finalized = indexer.get_last_finalized_block_id().await?.unwrap_or(0);
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
