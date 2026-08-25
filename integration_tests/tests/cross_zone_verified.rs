#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! Cross-zone round trip with the indexer in the loop (Option B). A ping on zone
//! A is delivered to zone B, and zone B's indexer independently re-derives the
//! injected dispatch from zone A's finalized blocks before applying it. The
//! payload landing in the indexer's state proves verification passed; a forgery
//! would have halted the indexer instead.

use std::time::Duration;

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use cross_zone_outbox_core::outbox_pda;
use integration_tests::{
    config::{self, SequencerPartialConfig},
    indexer_client::IndexerClient,
};
use lee::{AccountId, PublicTransaction, public_transaction::Message};
use lee_core::program::ProgramId;
use ping_core::{
    ReceiverInstruction, SenderInstruction, ping_record_pda, receiver_config_account_id,
    sender_config_account_id,
};
use sequencer_core::config::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute};
use sequencer_service_rpc::RpcClient as _;
use test_fixtures::{
    MultiZoneTestContextBuilder, ZoneTestContextBuilder, config::MultiNodeTestContextConfig,
};
use tokio::test;

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(600);
const PING_PAYLOAD: &[u8] = b"hello-verified-zone";

#[test]
async fn indexer_verifies_and_delivers_cross_zone_ping() -> Result<()> {
    let partial = SequencerPartialConfig::default();
    let channel_a = config::bedrock_channel_id();
    let channel_b = config::bedrock_channel_id_b();
    let zone_a: [u8; 32] = *channel_a.as_ref();
    let zone_b: [u8; 32] = *channel_b.as_ref();

    let receiver_id = programs::ping_receiver().id();
    let cross_zone = CrossZoneConfig {
        peers: vec![CrossZonePeer {
            channel_id: zone_a,
            allowed_routes: vec![CrossZoneRoute {
                src_program_id: programs::ping_sender().id(),
                target_program_id: receiver_id,
            }],
            expected_block_signing_pubkeys: Vec::new(),
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
            .with_genesis(vec![])
            .with_cross_zone(Some(cross_zone)),
        )
        .build()
        .await?;

    // Zone A: source. Zone B: destination, with the watcher on its sequencer and
    // the verifier on its indexer.
    let ind_client_b = ctx.indexer_client_zone(channel_b).unwrap();

    let seq_client_a = &ctx
        .zone_default_sequencer_component(channel_a)
        .sequencer_client;

    // Submit the ping on zone A, addressed to ping_receiver on zone B.
    let ping = build_ping_tx(zone_b, receiver_id);
    seq_client_a
        .send_transaction(ping)
        .await
        .context("Failed to submit ping on zone A")?;

    // Wait until zone B's indexer records the delivered payload. The indexer only
    // applies the dispatch after re-deriving and verifying it.
    let record_id = ping_record_pda(receiver_id);

    let delivered = wait_for_indexer_delivery(ind_client_b, record_id).await?;
    assert_eq!(
        delivered, PING_PAYLOAD,
        "Zone B's indexer must record the verified cross-zone payload"
    );
    Ok(())
}

fn build_ping_tx(target_zone: [u8; 32], receiver_id: ProgramId) -> LeeTransaction {
    let outbox_id = programs::cross_zone_outbox().id();
    let ordinal = 0;

    let payload = borsh::to_vec(&ReceiverInstruction::Record {
        payload: PING_PAYLOAD.to_vec(),
    })
    .expect("serialize ping instruction");

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

/// Polls zone B's indexer until the ping record PDA holds a payload.
async fn wait_for_indexer_delivery(
    indexer: &IndexerClient,
    record_id: AccountId,
) -> Result<Vec<u8>> {
    let account_id = indexer_service_protocol::AccountId {
        value: record_id.into_value(),
    };
    let wait = async {
        loop {
            let account =
                indexer_service_rpc::RpcClient::get_account(&**indexer, account_id).await?;
            let data = account
                .slots
                .get(&indexer_service_protocol::ProgramId(
                    programs::ping_receiver().id(),
                ))
                .map(|slot| slot.data.0.clone())
                .unwrap_or_default();
            if !data.is_empty() {
                return Ok::<Vec<u8>, anyhow::Error>(data);
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    };
    tokio::time::timeout(DELIVERY_TIMEOUT, wait)
        .await
        .context("Zone B's indexer did not record the payload in time")?
}
