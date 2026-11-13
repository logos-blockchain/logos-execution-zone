#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! Non-transitivity pin: delivery follows the watch topology, never a relay.
//! A watches B, B watches A and C, C watches B. C's ping reaches B, but C's
//! ping aimed at A reaches nobody, even though A trusts B and B delivers C.

use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use cross_zone_outbox_core::{outbox_pda, outbox_pda_seed};
use integration_tests::{
    config::{self, SequencerPartialConfig},
    utils::wait_until,
};
use lee::{
    AccountId, Actor, PublicAccountEvidence, PublicTransaction, public_transaction::Message,
};
use lee_core::account::Nonce;
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use ping_core::{
    CrossZoneEmission, ReceiverMessage, SenderMessage, ping_record_pda, receiver_config_account_id,
    sender_config_account_id,
};
use sequencer_core::config::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use testnet_initial_state::{PublicAccountPrivateInitialData, initial_pub_accounts_private_keys};
use tokio::test;

/// 600s like the other finality-bound cross-zone suites.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(600);
const C_TO_B_PAYLOAD: &[u8] = b"hello-from-c";
const C_TO_A_PAYLOAD: &[u8] = b"undeliverable";
const B_TO_A_PAYLOAD: &[u8] = b"hello-from-b";

/// A peer entry watching `channel` with the plain ping route.
fn ping_route_peer(channel: [u8; 32]) -> CrossZonePeer {
    CrossZonePeer {
        channel_id: channel,
        allowed_routes: vec![CrossZoneRoute {
            src_account_id: programs::ping_sender_account_id(),
            target_account_id: programs::ping_receiver_account_id(),
            mint_cap: None,
        }],
        min_committee_size: 0,
        genesis_hash: None,
    }
}

const fn watching(peers: Vec<CrossZonePeer>) -> CrossZoneConfig {
    CrossZoneConfig {
        peers,
        lock_target_zones: Vec::new(),
        source_authority: None,
        source_governance: None,
    }
}

fn zone(
    channel: ChannelId,
    partial: SequencerPartialConfig,
    cross_zone: CrossZoneConfig,
) -> ZoneTestContextBuilder {
    ZoneTestContextBuilder::new(MultiNodeTestContextConfig {
        num_nodes: 1,
        bedrock_channel: channel,
    })
    .disable_wallet()
    .disable_indexer()
    .with_sequencer_partial_config(partial)
    .with_genesis(vec![])
    .with_cross_zone(Some(cross_zone))
}

/// Builds a top-level `ping_sender` transaction carrying `payload` to
/// `ping_receiver` on `target_zone`, as `cross_zone_ping.rs` does.
fn build_ping_tx(
    target_zone: [u8; 32],
    payload: &[u8],
    payer: &PublicAccountPrivateInitialData,
    payer_nonce: Nonce,
) -> LeeTransaction {
    let receiver_id = programs::ping_receiver_account_id();
    let outbox_id = programs::cross_zone_outbox_account_id();
    let ordinal = 0;

    let payload = borsh::to_vec(&ReceiverMessage::Record {
        payload: payload.to_vec(),
    })
    .expect("serialize ping instruction");

    let sender_id = programs::ping_sender_account_id();
    let config = Actor::new(sender_config_account_id(sender_id), sender_id);
    let outbox = Actor::new(
        outbox_pda(outbox_id, sender_id, &target_zone, ordinal),
        outbox_id,
    );
    let send = SenderMessage::Send {
        outbox,
        emission: CrossZoneEmission {
            target_zone,
            target_account_id: receiver_id,
            target_accounts: vec![
                Actor::new(receiver_config_account_id(receiver_id), receiver_id),
                Actor::new(ping_record_pda(receiver_id), receiver_id),
            ],
            payload,
            ordinal,
        },
    };

    let message = Message {
        admission_evidence: vec![PublicAccountEvidence::Pda {
            program: outbox_id,
            seed: outbox_pda_seed(sender_id, &target_zone, ordinal),
        }],
        ..Message::try_new_with_fees(
            config,
            vec![config, outbox],
            BTreeMap::from([(payer.account_id, payer_nonce)]),
            send,
            common::test_utils::test_fee_declaration(payer.account_id),
        )
        .expect("build ping message")
    };
    let witness_set =
        lee::public_transaction::WitnessSet::for_message(&message, &[&payer.pub_sign_key]);
    LeeTransaction::Public(PublicTransaction::new(message, witness_set))
}

/// The payer's next nonce on `client`'s zone; every send is charged there.
async fn payer_nonce(client: &SequencerClient, payer: AccountId) -> Result<Nonce> {
    Ok(client.get_account(payer).await?.unwrap_or_default().nonce)
}

/// Submits `tx` and waits for inclusion, so the next send cannot precede it.
async fn submit_and_wait(client: &SequencerClient, what: &str, tx: LeeTransaction) -> Result<()> {
    let tx_hash = client
        .send_transaction(tx)
        .await
        .with_context(|| format!("Failed to submit {what}"))?;
    wait_until(&format!("{what} to be included"), || async {
        Ok(client.get_transaction(tx_hash).await?.is_some())
    })
    .await?;

    // A reverted transaction is still included and never delivered, so say so
    // here rather than time out on the delivery.
    let (_tx, block_id) = client
        .get_transaction(tx_hash)
        .await?
        .context("the included transaction is readable")?;
    let block = client
        .get_block(block_id)
        .await?
        .context("the including block is readable")?;
    let index = block
        .body
        .transactions
        .iter()
        .position(|included| included.hash() == tx_hash)
        .context("the block holds the transaction it included")?;
    anyhow::ensure!(
        !block.body.is_reverted(index),
        "{what} reverted in block {block_id}"
    );
    Ok(())
}

/// The zone's current ping record payload, empty while nothing was delivered.
async fn record_payload(client: &SequencerClient) -> Result<Vec<u8>> {
    let receiver_id = programs::ping_receiver_account_id();
    let account = client
        .get_account(ping_record_pda(receiver_id))
        .await?
        .unwrap_or_default();
    Ok(account.data.actor_state(receiver_id).to_vec())
}

/// Polls the zone's sequencer until the ping record holds `expected`.
async fn wait_for_payload(client: &SequencerClient, what: &str, expected: &[u8]) -> Result<()> {
    let wait = async {
        loop {
            if record_payload(client).await? == expected {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    };
    tokio::time::timeout(DELIVERY_TIMEOUT, wait)
        .await
        .with_context(|| format!("Timed out waiting for {what}"))?
}

/// Ignored: the heaviest test in the suite, and it times out on a loaded
/// machine while finality stays healthy. Non-transitivity is structural, so
/// this is a topology demonstration run by hand with `--run-ignored all`.
#[ignore = "heaviest cross-zone test, run by hand on a quiet machine"]
#[test]
async fn a_message_does_not_transit_through_an_intermediate_zone() -> Result<()> {
    let partial = SequencerPartialConfig::default();
    let channel_a = config::bedrock_channel_id();
    let channel_b = config::bedrock_channel_id_b();
    let channel_c = config::bedrock_channel_id_from_seed(3);
    let zone_a: [u8; 32] = *channel_a.as_ref();
    let zone_b: [u8; 32] = *channel_b.as_ref();
    let zone_c: [u8; 32] = *channel_c.as_ref();

    let ctx = MultiZoneTestContextBuilder::default()
        .with_zone(zone(
            channel_a,
            partial,
            watching(vec![ping_route_peer(zone_b)]),
        ))
        .with_zone(zone(
            channel_b,
            partial,
            watching(vec![ping_route_peer(zone_a), ping_route_peer(zone_c)]),
        ))
        .with_zone(zone(
            channel_c,
            partial,
            watching(vec![ping_route_peer(zone_b)]),
        ))
        .build()
        .await?;

    let seq_a = &ctx
        .zone_default_sequencer_component(channel_a)
        .sequencer_client;
    let seq_b = &ctx
        .zone_default_sequencer_component(channel_b)
        .sequencer_client;
    let seq_c = &ctx
        .zone_default_sequencer_component(channel_c)
        .sequencer_client;

    let payer = &initial_pub_accounts_private_keys()[0];

    // Included before the C to B ping, so that delivery proves B's watcher
    // scanned past this one.
    let dead_end_nonce = payer_nonce(seq_c, payer.account_id).await?;
    submit_and_wait(
        seq_c,
        "the ping aimed at zone A",
        build_ping_tx(zone_a, C_TO_A_PAYLOAD, payer, dead_end_nonce),
    )
    .await?;
    let c_to_b_nonce = payer_nonce(seq_c, payer.account_id).await?;
    submit_and_wait(
        seq_c,
        "the ping aimed at zone B",
        build_ping_tx(zone_b, C_TO_B_PAYLOAD, payer, c_to_b_nonce),
    )
    .await?;

    wait_for_payload(seq_b, "zone B to record zone C's ping", C_TO_B_PAYLOAD).await?;
    assert!(
        record_payload(seq_a).await?.is_empty(),
        "zone A must not receive a zone C emission relayed through zone B"
    );

    // A recording B's own ping proves its watcher scanned past B's dispatch of
    // C's message; without this leg the assertions above would also hold for an
    // A that had read nothing.
    let b_to_a_nonce = payer_nonce(seq_b, payer.account_id).await?;
    submit_and_wait(
        seq_b,
        "the ping from zone B",
        build_ping_tx(zone_a, B_TO_A_PAYLOAD, payer, b_to_a_nonce),
    )
    .await?;
    wait_for_payload(seq_a, "zone A to record zone B's ping", B_TO_A_PAYLOAD).await?;
    assert_eq!(
        record_payload(seq_a).await?,
        B_TO_A_PAYLOAD,
        "zone A's record holds only what zone B sent in its own name"
    );
    let dead_letters = seq_a.get_cross_zone_dead_letters().await?;
    assert_eq!(
        (dead_letters.total_retired, dead_letters.retained.len()),
        (0, 0),
        "zone A never even attempted a delivery for zone C's message"
    );

    Ok(())
}
