#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! A sequencer restart must resume its cross-zone watcher from the persisted per-peer delivery
//! floor instead of re-reading the peer channel from genesis.

use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use integration_tests::{
    config::{self, SequencerPartialConfig},
    setup::{SequencerSetup, sequencer_client, setup_bedrock_node},
};
use lee::{AccountId, Actor, PublicTransaction, public_transaction::Message};
use lee_core::account::Nonce;
use ping_core::{ReceiverMessage, SenderMessage, ping_record_pda, receiver_config_account_id};
use sequencer_core::config::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{config::source_only_cross_zone, init_logger};
use testnet_initial_state::{PublicAccountPrivateInitialData, initial_pub_accounts_private_keys};
use tokio::test;

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(480);
const BLOCKS_AFTER_RESTART: u64 = 5;
const RESTART_TIMEOUT: Duration = Duration::from_secs(240);
const PING_PAYLOAD: &[u8] = b"hello-cross-zone";

#[test]
async fn restarted_watcher_resumes_instead_of_replaying_the_peer_channel() -> Result<()> {
    init_logger();

    let (_bedrock, bedrock_addr) = setup_bedrock_node()
        .await
        .context("Failed to set up shared Bedrock node")?;

    let partial = SequencerPartialConfig {
        priority_fee_percent: 150,
        ..SequencerPartialConfig::default()
    };
    let channel_a = config::bedrock_channel_id();
    let channel_b = config::bedrock_channel_id_b();
    let zone_a: [u8; 32] = *channel_a.as_ref();
    let zone_b: [u8; 32] = *channel_b.as_ref();
    let receiver_id = programs::ping_receiver_account_id();

    let cross_zone = CrossZoneConfig {
        peers: vec![CrossZonePeer {
            channel_id: zone_a,
            allowed_routes: vec![CrossZoneRoute {
                src_account_id: programs::ping_sender_account_id(),
                target_account_id: receiver_id,
                mint_cap: None,
            }],
            min_committee_size: 0,
            genesis_hash: None,
        }],
        lock_target_zones: Vec::new(),
        source_authority: None,
        source_governance: None,
    };

    let (seq_a, _seq_a_home) = SequencerSetup::new(partial, bedrock_addr)
        .with_channel_id(channel_a)
        .with_genesis(vec![])
        .with_cross_zone(source_only_cross_zone())
        .setup()
        .await
        .context("Failed to set up zone A sequencer")?;

    let home_b = tempfile::tempdir().context("Failed to create zone B home")?;
    let mut seq_b = SequencerSetup::new(partial, bedrock_addr)
        .with_channel_id(channel_b)
        .with_genesis(vec![])
        .with_cross_zone(cross_zone.clone())
        .setup_at(home_b.path())
        .await
        .context("Failed to set up zone B sequencer")?;

    let seq_client_a = sequencer_client(seq_a.addr())?;
    let payer = &initial_pub_accounts_private_keys()[0];
    let payer_nonce = seq_client_a
        .get_account(payer.account_id)
        .await?
        .unwrap_or_default()
        .nonce;
    seq_client_a
        .send_transaction(build_ping_tx(zone_b, receiver_id, payer, payer_nonce))
        .await
        .context("Failed to submit ping on zone A")?;
    let record_id = ping_record_pda(receiver_id);
    let delivered =
        wait_for_delivery(sequencer_client(seq_b.addr())?, record_id, receiver_id).await?;
    assert_eq!(
        delivered, PING_PAYLOAD,
        "Zone B must record the payload before the restart"
    );

    let tip_before = sequencer_client(seq_b.addr())?.get_last_block_id().await?;

    seq_b.shutdown().await;
    seq_b = SequencerSetup::new(partial, bedrock_addr)
        .with_channel_id(channel_b)
        .with_genesis(vec![])
        .with_cross_zone(cross_zone)
        .setup_at(home_b.path())
        .await
        .context("Failed to restart zone B sequencer")?;
    let client_b = sequencer_client(seq_b.addr())?;

    let tip_after = wait_for_block_id(
        &client_b,
        tip_before.saturating_add(BLOCKS_AFTER_RESTART),
        RESTART_TIMEOUT,
    )
    .await?;

    let replayed = count_inbox_transactions(&client_b, tip_before.saturating_add(1), tip_after)
        .await
        .context("Failed to scan zone B blocks after the restart")?;
    assert_eq!(
        replayed,
        0,
        "a restarted watcher must resume from its persisted delivery floor; found {replayed} inbox transaction(s) in blocks {}..={tip_after}, which means it re-read the peer channel from genesis",
        tip_before.saturating_add(1)
    );

    let account = client_b.get_account(record_id).await?.unwrap_or_default();
    assert_eq!(
        account.data.actor_state(receiver_id).to_vec(),
        PING_PAYLOAD,
        "the delivered payload must survive the restart"
    );
    Ok(())
}

async fn count_inbox_transactions(client: &SequencerClient, from: u64, to: u64) -> Result<usize> {
    let inbox_id = programs::cross_zone_inbox_account_id();
    let mut count = 0_usize;
    for block_id in from..=to {
        let Some(block) = client.get_block(block_id).await? else {
            continue;
        };
        for tx in &block.body.transactions {
            if let LeeTransaction::Public(public_tx) = tx
                && public_tx
                    .message()
                    .execution
                    .root
                    .to
                    .actor()
                    .program_account_id
                    == inbox_id
            {
                count = count.saturating_add(1);
            }
        }
    }
    Ok(count)
}

async fn wait_for_block_id(
    client: &SequencerClient,
    target: u64,
    timeout: Duration,
) -> Result<u64> {
    let wait = async {
        loop {
            let tip = client.get_last_block_id().await?;
            if tip >= target {
                return Ok::<u64, anyhow::Error>(tip);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };
    tokio::time::timeout(timeout, wait)
        .await
        .context("Zone B did not produce enough blocks after the restart")?
}

fn build_ping_tx(
    target_zone: [u8; 32],
    receiver_id: AccountId,
    payer: &PublicAccountPrivateInitialData,
    payer_nonce: Nonce,
) -> LeeTransaction {
    let payload = borsh::to_vec(&ReceiverMessage::Record {
        payload: PING_PAYLOAD.to_vec(),
    })
    .expect("serialize ping message");

    let sender_id = programs::ping_sender_account_id();
    let sender = Actor::new(sender_id, sender_id);
    let send = SenderMessage::Send {
        target_zone,
        target: Actor::new(receiver_id, receiver_id),
        accounts: vec![
            Actor::new(receiver_config_account_id(receiver_id), receiver_id),
            Actor::new(ping_record_pda(receiver_id), receiver_id),
        ],
        payload,
    };

    let message = Message::try_new_with_fees(
        sender,
        vec![sender],
        BTreeMap::from([(payer.account_id, payer_nonce)]),
        send,
        common::test_utils::test_fee_declaration(payer.account_id),
    )
    .expect("build ping message");
    let witness_set =
        lee::public_transaction::WitnessSet::for_message(&message, &[&payer.pub_sign_key]);
    LeeTransaction::Public(PublicTransaction::new(message, witness_set))
}

async fn wait_for_delivery(
    client: SequencerClient,
    record_id: AccountId,
    receiver_id: AccountId,
) -> Result<Vec<u8>> {
    let wait = async {
        loop {
            let account = client.get_account(record_id).await?.unwrap_or_default();
            let data = account.data.actor_state(receiver_id).to_vec();
            if !data.is_empty() {
                return Ok::<Vec<u8>, anyhow::Error>(data);
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    };
    tokio::time::timeout(DELIVERY_TIMEOUT, wait)
        .await
        .context("Zone B did not record the cross-zone payload in time")?
}
