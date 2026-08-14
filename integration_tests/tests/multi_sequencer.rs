#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! Two sequencers share one channel: A starts solo as channel admin, live-
//! accredits `[A, B]` with round-robin rotation, B joins and syncs, both
//! produce on their turns, and A, B and an indexer converge on the same chain.

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use indexer_service_rpc::RpcClient as _;
use integration_tests::{
    config::{self, SequencerPartialConfig},
    indexer_client::IndexerClient,
};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};
use tokio::test;

const PHASE_TIMEOUT: Duration = Duration::from_secs(360);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const TRANSFER_AMOUNT: u128 = 10;
/// ≈4 turn windows past B's join (5 s blocks, ~20 s turns → ~4 blocks/window).
const ROTATION_BLOCKS: u64 = 8;

#[test]
async fn multi_sequencer_committee_converges() -> Result<()> {
    let bedrock_channel_id = config::bedrock_channel_id();
    let partial = SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(5),
        ..SequencerPartialConfig::default()
    };

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 2,
                bedrock_channel: bedrock_channel_id,
            })
            .disable_wallet()
            .with_sequencer_partial_config(partial)
            .with_genesis(vec![]),
        )
        .build()
        .await?;

    let mut seq_iterator = ctx.sequencer_components_iter(bedrock_channel_id).unwrap();

    let seq_client_a = &(seq_iterator.next().unwrap().sequencer_client);
    let seq_client_b = &(seq_iterator.next().unwrap().sequencer_client);

    let indexer = ctx.indexer_client();

    wait_for_height(seq_client_a, 2, "sequencer A to produce past genesis").await?;

    log::info!("Passed wait for height A to be at least 2");

    let height_at_config = seq_client_a.get_last_block_id().await?;
    wait_for_height(
        seq_client_a,
        height_at_config + 1,
        "A to produce after the roster change",
    )
    .await?;

    log::info!(
        "Passed wait for height A to be at least {}",
        height_at_config + 1
    );

    let join_height = seq_client_a.get_last_block_id().await?;
    wait_for_height(seq_client_b, join_height, "B to sync to A's height at join").await?;

    log::info!("Passed wait for height B to be at least {join_height}");

    // Phase 4: rotation + convergence over ≈4 turn windows.
    let rotation_target = join_height + ROTATION_BLOCKS;
    wait_for_height(
        seq_client_a,
        rotation_target,
        "the chain to advance across turn windows",
    )
    .await?;

    log::info!("Passed wait for height A to be at least {rotation_target}");

    wait_for_height(
        seq_client_b,
        rotation_target,
        "B to follow across turn windows",
    )
    .await?;
    assert_same_chain(seq_client_a, seq_client_b).await?;

    log::info!("Passed wait for height B to be at least {rotation_target}");

    // Phase 5: a tx submitted only to B is included by B and visible on A.
    let accounts = initial_public_user_accounts();
    let from = accounts[0].account_id;
    let to = accounts[1].account_id;
    let sign_key = initial_pub_accounts_private_keys()[0].pub_sign_key.clone();

    let to_balance_before = seq_client_a.get_account_balance(to).await?;
    let nonce = seq_client_b.get_accounts_nonces(vec![from]).await?[0];
    let tx = common::test_utils::create_transaction_native_token_transfer(
        from,
        nonce.0,
        to,
        TRANSFER_AMOUNT,
        &sign_key,
    );
    seq_client_b
        .send_transaction(tx)
        .await
        .context("Failed to submit the transfer to B")?;

    wait_for_balance(seq_client_a, to, to_balance_before + TRANSFER_AMOUNT).await?;

    log::info!(
        "Passed wait for height balance {to} to be {}",
        to_balance_before + TRANSFER_AMOUNT
    );

    // Phase 6: the indexer finalizes the same chain, with no stall.
    wait_for_finalized(indexer, join_height).await?;

    log::info!("Passed indexer to see finalized {join_height}");

    let finalized = indexer.get_last_finalized_block_id().await?.unwrap_or(0);
    for id in 1..=finalized {
        let block_i = indexer
            .get_block_by_id(id)
            .await?
            .with_context(|| format!("Indexer is missing finalized block {id}"))?;
        let block_a = seq_client_a
            .get_block(id)
            .await?
            .with_context(|| format!("A is missing block {id}"))?;
        ensure!(
            block_i.header.hash == indexer_service_protocol::HashType::from(block_a.header.hash),
            "Indexer diverges from A at block {id}"
        );
    }
    let status = indexer.get_status().await?;
    ensure!(
        status.stall_reason.is_none(),
        "Indexer is stalled: {:?}",
        status.stall_reason
    );

    Ok(())
}

/// Polls the sequencer until its chain height reaches `target`.
async fn wait_for_height(client: &SequencerClient, target: u64, what: &str) -> Result<()> {
    log::info!("Waiting for {what:?}, target is {target}");

    let wait = async {
        loop {
            if client.get_last_block_id().await? >= target {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    };
    tokio::time::timeout(PHASE_TIMEOUT, wait)
        .await
        .with_context(|| format!("Timed out waiting for {what} (target height {target})"))?
}

/// Polls the sequencer until `account`'s balance reaches `expected`.
async fn wait_for_balance(
    client: &SequencerClient,
    account: lee::AccountId,
    expected: u128,
) -> Result<()> {
    log::info!("Waiting for {account} to have {expected} tokens");

    let wait = async {
        loop {
            if client.get_account_balance(account).await? == expected {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    };
    tokio::time::timeout(PHASE_TIMEOUT, wait)
        .await
        .context("Timed out waiting for the cross-sequencer transfer to reach A")?
}

/// Polls the indexer until its finalized height reaches `target`.
async fn wait_for_finalized(indexer: &IndexerClient, target: u64) -> Result<()> {
    log::info!("Waiting for indexer to see target finalized, target is {target}");

    let wait = async {
        loop {
            if indexer.get_last_finalized_block_id().await?.unwrap_or(0) >= target {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    };
    tokio::time::timeout(PHASE_TIMEOUT, wait)
        .await
        .context("Timed out waiting for the indexer to finalize")?
}

/// Asserts A and B hold byte-identical block hashes over their common prefix.
async fn assert_same_chain(a: &SequencerClient, b: &SequencerClient) -> Result<()> {
    let common = a
        .get_last_block_id()
        .await?
        .min(b.get_last_block_id().await?);
    for id in 1..=common {
        let block_a = a
            .get_block(id)
            .await?
            .with_context(|| format!("A is missing block {id}"))?;
        let block_b = b
            .get_block(id)
            .await?
            .with_context(|| format!("B is missing block {id}"))?;
        ensure!(
            block_a.header.hash == block_b.header.hash,
            "Chain divergence at block {id}: A {:?} vs B {:?}",
            block_a.header.hash,
            block_b.header.hash
        );
    }
    Ok(())
}
