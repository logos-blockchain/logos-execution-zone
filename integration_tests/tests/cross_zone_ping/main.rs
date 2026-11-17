#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! End-to-end cross-zone round trip: a ping submitted on zone A is delivered by zone B's watcher to
//! `ping_receiver` on zone B, which records the payload.

use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use integration_tests::config::{self, SequencerPartialConfig};
use lee::{AccountId, Actor, PublicTransaction, public_transaction::Message};
use lee_core::account::Nonce;
use ping_core::{ReceiverMessage, SenderMessage, ping_record_pda, receiver_config_account_id};
use sequencer_core::config::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder,
    config::{MultiNodeTestContextConfig, source_only_cross_zone},
};
use testnet_initial_state::{PublicAccountPrivateInitialData, initial_pub_accounts_private_keys};
use tokio::test;

mod any_program;
mod three_zones;

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(480);
const PING_PAYLOAD: &[u8] = b"hello-cross-zone";

#[test]
async fn ping_crosses_from_zone_a_to_zone_b() -> Result<()> {
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

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 1,
                bedrock_channel: channel_a,
            })
            .disable_wallet()
            .disable_indexer()
            .with_sequencer_partial_config(partial)
            .with_genesis(vec![])
            .with_cross_zone(Some(source_only_cross_zone())),
        )
        .with_zone(
            ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
                num_nodes: 1,
                bedrock_channel: channel_b,
            })
            .disable_wallet()
            .disable_indexer()
            .with_sequencer_partial_config(partial)
            .with_genesis(vec![])
            .with_cross_zone(Some(cross_zone)),
        )
        .build()
        .await?;

    let seq_client_a = &ctx
        .zone_default_sequencer_component(channel_a)
        .sequencer_client;

    let seq_client_b = &ctx
        .zone_default_sequencer_component(channel_b)
        .sequencer_client;

    let payer = &initial_pub_accounts_private_keys()[0];
    let payer_nonce = seq_client_a
        .get_account(payer.account_id)
        .await?
        .unwrap_or_default()
        .nonce;
    let ping = build_ping_tx(zone_b, receiver_id, payer, payer_nonce);

    seq_client_a
        .send_transaction(ping)
        .await
        .context("Failed to submit ping on zone A")?;

    let record_id = ping_record_pda(receiver_id);
    let delivered = wait_for_delivery(seq_client_b.clone(), record_id, receiver_id).await?;

    assert_eq!(
        delivered, PING_PAYLOAD,
        "Zone B must record the payload delivered from zone A"
    );
    Ok(())
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
    .expect("serialize ping instruction");

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
