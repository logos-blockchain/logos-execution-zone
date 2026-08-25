#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! Gossip end-to-end: two sequencers share one channel with p2p gossip on,
//! and B's block production is disabled. A transfer submitted to B's RPC can
//! therefore only be included if gossip hands it to A — without gossip it
//! would sit in B's mempool forever and the test times out.

use std::time::Duration;

use anyhow::{Context as _, Result};
use integration_tests::config::{self, SequencerPartialConfig};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};
use tokio::test;

const PHASE_TIMEOUT: Duration = Duration::from_secs(360);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const TRANSFER_AMOUNT: u128 = 10;

#[test]
async fn gossiped_transaction_reaches_producing_sequencer() -> Result<()> {
    let bedrock_channel_id = config::bedrock_channel_id();
    let partial = SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(5),
        ..SequencerPartialConfig::default()
    };
    // B never produces: its production timer is longer than the test, so its
    // local mempool is a dead end and inclusion proves gossip delivery to A.
    let follower_partial = SequencerPartialConfig {
        block_create_timeout: Duration::from_secs(100_000),
        ..SequencerPartialConfig::default()
    };

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 2,
                bedrock_channel: bedrock_channel_id,
            })
            .disable_wallet()
            .disable_indexer()
            .with_sequencer_partial_config(partial)
            .with_follower_sequencer_partial_config(follower_partial)
            .with_gossip()
            .with_genesis(vec![]),
        )
        .build()
        .await?;

    let mut seq_iterator = ctx.sequencer_components_iter(bedrock_channel_id).unwrap();

    let seq_client_a = &(seq_iterator.next().unwrap().sequencer_client);
    let seq_client_b = &(seq_iterator.next().unwrap().sequencer_client);

    wait_for_height(seq_client_a, 2, "sequencer A to produce past genesis").await?;

    // B follows the chain via L1 even though it never produces.
    let sync_target = seq_client_a.get_last_block_id().await?;
    wait_for_height(seq_client_b, sync_target, "B to sync to A's height").await?;

    let accounts = initial_public_user_accounts();
    let from = accounts[0].account_id;
    let to = accounts[1].account_id;
    let sign_key = initial_pub_accounts_private_keys()[0].pub_sign_key.clone();

    let to_balance_before = seq_client_a
        .get_account_balance(to, programs::authenticated_transfer().id())
        .await?;
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

    // Only A produces, so the balance changing on A proves the transaction
    // crossed the gossip mesh from B.
    wait_for_balance(seq_client_a, to, to_balance_before + TRANSFER_AMOUNT).await?;

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
            if client
                .get_account_balance(account, programs::authenticated_transfer().id())
                .await?
                == expected
            {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    };
    tokio::time::timeout(PHASE_TIMEOUT, wait)
        .await
        .context("Timed out waiting for the gossiped transfer to be included by A")?
}
