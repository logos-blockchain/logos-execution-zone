#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! End-to-end cross-zone round trip: a ping submitted on zone A is delivered by
//! zone B's watcher to `ping_receiver` on zone B, which records the payload.
//!
//! Two sequencers share one Bedrock node (no indexers): zone A publishes the
//! ping to Bedrock, zone B's watcher reads zone A's finalized blocks, injects the
//! inbox dispatch, and zone B's sequencer delivers it. This is the M3 milestone,
//! sequencer-trusted, with no indexer re-derivation (that is M4).

use std::time::Duration;

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use cross_zone_outbox_core::outbox_pda;
use integration_tests::config::{self, SequencerPartialConfig};
use lee::{AccountId, PublicTransaction, public_transaction::Message};
use lee_core::program::ProgramId;
use ping_core::{
    ReceiverInstruction, SenderInstruction, ping_record_pda, receiver_config_account_id,
    sender_config_account_id,
};
use sequencer_core::config::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use tokio::test;

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(480);
const PING_PAYLOAD: &[u8] = b"hello-cross-zone";

#[test]
async fn ping_crosses_from_zone_a_to_zone_b() -> Result<()> {
    let partial = SequencerPartialConfig::default();
    let channel_a = config::bedrock_channel_id();
    let channel_b = config::bedrock_channel_id_b();
    let zone_a: [u8; 32] = *channel_a.as_ref();
    let zone_b: [u8; 32] = *channel_b.as_ref();

    let receiver_id = programs::ping_receiver().id();

    // Zone B watches zone A and allows delivery only to ping_receiver.
    let cross_zone = CrossZoneConfig {
        peers: vec![CrossZonePeer {
            channel_id: zone_a,
            allowed_routes: vec![CrossZoneRoute {
                src_program_id: programs::ping_sender().id(),
                target_program_id: receiver_id,
            }],
            expected_block_signing_pubkey: None,
        }],
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
            .with_genesis(vec![]),
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

    // Submit the ping on zone A, addressed to ping_receiver on zone B.
    let ping = build_ping_tx(zone_b, receiver_id);

    let seq_client_a = &ctx
        .zone_default_sequencer_component(channel_a)
        .sequencer_client;

    let seq_client_b = &ctx
        .zone_default_sequencer_component(channel_b)
        .sequencer_client;

    seq_client_a
        .send_transaction(ping)
        .await
        .context("Failed to submit ping on zone A")?;

    // Wait until zone B's sequencer records the delivered payload.
    let record_id = ping_record_pda(receiver_id);
    let delivered = wait_for_delivery(seq_client_b.clone(), record_id).await?;

    assert_eq!(
        delivered, PING_PAYLOAD,
        "Zone B must record the payload delivered from zone A"
    );
    Ok(())
}

/// Builds a top-level `ping_sender` transaction that chains into the outbox to emit
/// a message carrying a `ping_receiver::Record` instruction for the target zone.
fn build_ping_tx(target_zone: [u8; 32], receiver_id: ProgramId) -> LeeTransaction {
    let outbox_id = programs::cross_zone_outbox().id();
    let ordinal = 0;

    // The payload is the ping_receiver instruction, serialized as risc0 words in
    // little-endian bytes (the contract the inbox reverses when forwarding).
    let words = risc0_zkvm::serde::to_vec(&ReceiverInstruction::Record {
        payload: PING_PAYLOAD.to_vec(),
    })
    .expect("serialize ping instruction");
    let payload: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();

    let send = SenderInstruction::Send {
        target_zone,
        target_program_id: receiver_id,
        target_accounts: vec![
            receiver_config_account_id(receiver_id).into_value(),
            ping_record_pda(receiver_id).into_value(),
        ],
        payload,
        ordinal,
    };

    let sender_id = programs::ping_sender().id();
    let outbox_account = outbox_pda(outbox_id, sender_id, &target_zone, ordinal);
    let message = Message::try_new(
        sender_id,
        vec![sender_config_account_id(sender_id), outbox_account],
        vec![],
        send,
    )
    .expect("build ping message");
    LeeTransaction::Public(PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    ))
}

/// Polls zone B's sequencer until the ping record PDA holds a payload.
async fn wait_for_delivery(client: SequencerClient, record_id: AccountId) -> Result<Vec<u8>> {
    let wait = async {
        loop {
            let account = client.get_account(record_id).await?;
            let data = account.data.into_inner();
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
