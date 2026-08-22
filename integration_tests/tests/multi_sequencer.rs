#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! Two sequencers share one channel: both are staked at genesis, so the channel
//! is created already accrediting `[A, B]`, B syncs the chain A began, both
//! produce on their turns, and A, B and an indexer converge on the same chain.

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use indexer_service_rpc::RpcClient as _;
use integration_tests::{
    assert_same_chain, committee,
    config::{self, SequencerPartialConfig},
    init_logger, wait_until,
};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use sequencer_core::config::BedrockConfig;
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};
use tokio::test;

const TRANSFER_AMOUNT: u128 = 10;
/// ≈4 turn windows, at the `system_accounts` posting timeframe and 5 s blocks.
const ROTATION_BLOCKS: u64 = 8;

#[test]
async fn multi_sequencer_committee_converges() -> Result<()> {
    init_logger();

    let channel = config::bedrock_channel_id();
    let partial = SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(5),
        ..SequencerPartialConfig::default()
    };

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 2,
                bedrock_channel: channel,
            })
            .disable_wallet()
            .with_sequencer_partial_config(partial),
        )
        .build()
        .await
        .context("Failed to build the two-sequencer test context")?;

    let a = ctx
        .sequencer_client_by_node_ids(channel, 0)
        .context("Missing sequencer A")?;
    let b = ctx
        .sequencer_client_by_node_ids(channel, 1)
        .context("Missing sequencer B")?;
    let indexer = ctx.indexer_client();

    let pub_a = Ed25519Key::from_bytes(&config::SEQUENCER_SIGNING_KEY).public_key();
    let pub_b = Ed25519Key::from_bytes(&config::sequencer_signing_key_from_seed(1)).public_key();

    let bedrock_config = BedrockConfig {
        channel_id: channel,
        node_url: config::addr_to_url(config::UrlProtocol::Http, ctx.bedrock_addr())?,
        funding_key: config::bedrock_funding_key(),
        auth: None,
        priority_fee: sequencer_core::config::default_priority_fee(),
    };

    // Phase 1: both keys accredited from channel creation.
    let mut want = vec![pub_a.to_bytes(), pub_b.to_bytes()];
    want.sort_unstable();
    wait_until("Bedrock to accredit both staked keys", || async {
        Ok(committee(&bedrock_config).await?.0 == want)
    })
    .await?;

    // Phase 2: B follows the chain A began.
    let join_height = a.get_last_block_id().await?.max(1);
    wait_for_height(b, join_height, "B to sync to A's height").await?;

    // Phase 3: rotation + convergence; without the turn check, a chain A
    // produces alone satisfies everything below.
    let rotation_target = join_height + ROTATION_BLOCKS;
    wait_for_height(
        a,
        rotation_target,
        "the chain to advance across turn windows",
    )
    .await?;
    wait_for_height(b, rotation_target, "B to follow across turn windows").await?;
    wait_until("the round-robin turn to reach B", || async {
        Ok(committee(&bedrock_config).await?.1 == Some(pub_b))
    })
    .await?;
    assert_same_chain(a, b).await?;

    // Phase 4: a tx submitted only to B is included by B and visible on A.
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

    let expected = to_balance_before + TRANSFER_AMOUNT;
    wait_until("the cross-sequencer transfer to reach A", || async {
        Ok(a.get_account_balance(to).await? == expected)
    })
    .await?;

    // Phase 5: the indexer finalizes the same chain, with no stall.
    wait_until("the indexer to finalize", || async {
        Ok(indexer.get_last_finalized_block_id().await?.unwrap_or(0) >= join_height)
    })
    .await?;
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
    wait_until(&format!("{what} (target height {target})"), || async {
        Ok(client.get_last_block_id().await? >= target)
    })
    .await
}
