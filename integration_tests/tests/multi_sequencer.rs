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
    setup::{SequencerSetup, indexer_client, sequencer_client, setup_bedrock_node, setup_indexer},
};
use logos_blockchain_key_management_system_service::keys::{ED25519_SECRET_KEY_SIZE, Ed25519Key};
use sequencer_core::{block_publisher::post_channel_config, config::BedrockConfig};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};
use tokio::test;

/// 1 s bedrock slots: rotate the turn every ~20 s of tenure; steal a stalled
/// turn after ~30 s (bounds the stall while B is accredited but not started).
const POSTING_TIMEFRAME_SLOTS: u32 = 20;
const POSTING_TIMEOUT_SLOTS: u32 = 30;
const PHASE_TIMEOUT: Duration = Duration::from_secs(360);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const TRANSFER_AMOUNT: u128 = 10;
/// ≈4 turn windows past B's join (5 s blocks, ~20 s turns → ~4 blocks/window).
const ROTATION_BLOCKS: u64 = 8;

#[test]
async fn multi_sequencer_committee_converges() -> Result<()> {
    let (_bedrock, bedrock_addr) = setup_bedrock_node()
        .await
        .context("Failed to set up Bedrock node")?;

    // Fixed seeds so A can accredit B's public key before B exists.
    let key_a = [0xA1_u8; ED25519_SECRET_KEY_SIZE];
    let key_b = [0xB2_u8; ED25519_SECRET_KEY_SIZE];
    let pub_a = Ed25519Key::from_bytes(&key_a).public_key();
    let pub_b = Ed25519Key::from_bytes(&key_b).public_key();

    let partial = SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(5),
        ..SequencerPartialConfig::default()
    };

    // Phase 1: A solo (its first inscription creates the channel), plus an indexer.
    let (seq_a, _a_home) = SequencerSetup::new(partial, bedrock_addr)
        .with_genesis(vec![])
        .with_bedrock_signing_key(key_a)
        .setup()
        .await
        .context("Failed to set up sequencer A")?;
    let a = sequencer_client(seq_a.addr())?;
    let (idx, _idx_home) = setup_indexer(bedrock_addr, config::bedrock_channel_id(), None)
        .await
        .context("Failed to set up indexer")?;
    let indexer = indexer_client(idx.addr()).await?;

    wait_for_height(&a, 2, "sequencer A to produce past genesis").await?;

    // Phase 2: live roster change to [A, B] with rotation enabled, posted
    // straight to bedrock with A's admin key (the operator one-shot path).
    post_channel_config(
        &BedrockConfig {
            channel_id: config::bedrock_channel_id(),
            node_url: config::addr_to_url(config::UrlProtocol::Http, bedrock_addr)?,
            funding_key: config::bedrock_funding_key(),
            auth: None,
            priority_fee: sequencer_core::config::default_priority_fee(),
        },
        &Ed25519Key::from_bytes(&key_a),
        vec![pub_a, pub_b],
        POSTING_TIMEFRAME_SLOTS,
        POSTING_TIMEOUT_SLOTS,
        1,
        1,
    )
    .await
    .context("Failed to configure the channel committee")?;

    let height_at_config = a.get_last_block_id().await?;
    wait_for_height(
        &a,
        height_at_config + 1,
        "A to produce after the roster change",
    )
    .await?;

    // Phase 3: B joins live and syncs the existing chain.
    let (seq_b, _b_home) = SequencerSetup::new(partial, bedrock_addr)
        .with_genesis(vec![])
        .with_bedrock_signing_key(key_b)
        .setup()
        .await
        .context("Failed to set up sequencer B")?;
    let b = sequencer_client(seq_b.addr())?;

    let join_height = a.get_last_block_id().await?;
    wait_for_height(&b, join_height, "B to sync to A's height at join").await?;

    // Phase 4: rotation + convergence over ≈4 turn windows.
    let rotation_target = join_height + ROTATION_BLOCKS;
    wait_for_height(
        &a,
        rotation_target,
        "the chain to advance across turn windows",
    )
    .await?;
    wait_for_height(&b, rotation_target, "B to follow across turn windows").await?;
    assert_same_chain(&a, &b).await?;

    // Phase 5: a tx submitted only to B is included by B and visible on A.
    let accounts = initial_public_user_accounts();
    let from = accounts[0].account_id;
    let to = accounts[1].account_id;
    let sign_key = initial_pub_accounts_private_keys()[0].pub_sign_key.clone();

    let to_balance_before = a.get_account_balance(to).await?;
    let nonce = b.get_accounts_nonces(vec![from]).await?[0];
    let tx = common::test_utils::create_transaction_native_token_transfer(
        from,
        nonce.0,
        to,
        TRANSFER_AMOUNT,
        &sign_key,
    );
    b.send_transaction(tx)
        .await
        .context("Failed to submit the transfer to B")?;

    wait_for_balance(&a, to, to_balance_before + TRANSFER_AMOUNT).await?;

    // Phase 6: the indexer finalizes the same chain, with no stall.
    wait_for_finalized(&indexer, join_height).await?;
    let finalized = indexer.get_last_finalized_block_id().await?.unwrap_or(0);
    for id in 1..=finalized {
        let block_i = indexer
            .get_block_by_id(id)
            .await?
            .with_context(|| format!("Indexer is missing finalized block {id}"))?;
        let block_a = a
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
