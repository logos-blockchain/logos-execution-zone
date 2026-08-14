#![expect(
    clippy::tests_outside_test_module,
    reason = "top-level test functions are conventional for integration tests"
)]

//! A sequencer restart must resume its cross-zone watcher from the persisted
//! per-peer delivery floor instead of re-reading the peer channel from genesis.
//!
//! Re-reading is safe (the dispatch key is content-addressed and the inbox
//! no-ops a replay) so on-chain state cannot tell the two apart. What does tell
//! them apart is the transactions: a watcher that lost its cursor re-injects
//! every already-delivered dispatch, which shows up as inbox transactions in
//! blocks produced after the restart. This is the only test that covers the
//! wiring from `spawn_watchers` through the store, so a silent regression here
//! would leave every other test green while the feature does nothing.

use std::time::Duration;

use anyhow::{Context as _, Result};
use common::transaction::LeeTransaction;
use cross_zone_outbox_core::outbox_pda;
use integration_tests::{
    config::{self, SequencerPartialConfig},
    setup::{SequencerSetup, sequencer_client, setup_bedrock_node},
};
use lee::{AccountId, PublicTransaction, public_transaction::Message};
use lee_core::program::ProgramId;
use ping_core::{
    ReceiverInstruction, SenderInstruction, ping_record_pda, receiver_config_account_id,
    sender_config_account_id,
};
use sequencer_core::config::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute};
use sequencer_service_rpc::{RpcClient as _, SequencerClient};
use tokio::test;

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(480);
/// Blocks zone B must produce after the restart before we judge the watcher.
/// A watcher that lost its cursor re-reads the peer channel on its first pass,
/// so a handful of blocks is ample room for the replay to appear.
const BLOCKS_AFTER_RESTART: u64 = 5;
const RESTART_TIMEOUT: Duration = Duration::from_secs(240);
const PING_PAYLOAD: &[u8] = b"hello-cross-zone";

#[test]
async fn restarted_watcher_resumes_instead_of_replaying_the_peer_channel() -> Result<()> {
    // Declared first so it outlives both zones (drops run in reverse order).
    let (_bedrock, bedrock_addr) = setup_bedrock_node()
        .await
        .context("Failed to set up shared Bedrock node")?;

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

    let (seq_a, _seq_a_home) = SequencerSetup::new(partial, bedrock_addr)
        .with_channel_id(channel_a)
        .with_genesis(vec![])
        .setup()
        .await
        .context("Failed to set up zone A sequencer")?;

    // Zone B keeps an explicit home so it can be restarted on the same store.
    let home_b = tempfile::tempdir().context("Failed to create zone B home")?;
    let mut seq_b = SequencerSetup::new(partial, bedrock_addr)
        .with_channel_id(channel_b)
        .with_genesis(vec![])
        .with_cross_zone(cross_zone.clone())
        .setup_at(home_b.path())
        .await
        .context("Failed to set up zone B sequencer")?;

    // Deliver one ping, so the peer channel holds a dispatch worth replaying.
    sequencer_client(seq_a.addr())?
        .send_transaction(build_ping_tx(zone_b, receiver_id))
        .await
        .context("Failed to submit ping on zone A")?;
    let record_id = ping_record_pda(receiver_id);
    let delivered = wait_for_delivery(sequencer_client(seq_b.addr())?, record_id).await?;
    assert_eq!(
        delivered, PING_PAYLOAD,
        "Zone B must record the payload before the restart"
    );

    let tip_before = sequencer_client(seq_b.addr())?.get_last_block_id().await?;

    // Restart zone B on the same home. Zone A stays quiet from here, so any
    // inbox transaction after the restart is a replay, not a new delivery.
    //
    // `shutdown` rather than `drop`: dropping aborts the main loop without
    // awaiting it and leaves the watchers and the publisher's drive task holding
    // the store, so the reopen below would race the `RocksDB` lock.
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

    // The delivery itself must survive the restart untouched.
    let account = client_b.get_account(record_id).await?;
    assert_eq!(
        account.data.into_inner(),
        PING_PAYLOAD,
        "the delivered payload must survive the restart"
    );
    Ok(())
}

/// Counts inbox transactions across `from..=to`, the signature of a re-injected
/// dispatch.
async fn count_inbox_transactions(client: &SequencerClient, from: u64, to: u64) -> Result<usize> {
    let inbox_id = programs::cross_zone_inbox().id();
    let mut count = 0_usize;
    for block_id in from..=to {
        let Some(block) = client.get_block(block_id).await? else {
            continue;
        };
        for tx in &block.body.transactions {
            if let LeeTransaction::Public(public_tx) = tx
                && public_tx.message().program_account_id == inbox_id.into()
            {
                count = count.saturating_add(1);
            }
        }
    }
    Ok(count)
}

/// Waits until the sequencer's tip reaches `target`, returning the tip.
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

/// Builds a top-level `ping_sender` transaction that chains into the outbox to emit
/// a message carrying a `ping_receiver::Record` instruction for the target zone.
fn build_ping_tx(target_zone: [u8; 32], receiver_id: ProgramId) -> LeeTransaction {
    let outbox_id = programs::cross_zone_outbox().id();
    let ordinal = 0;

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
        sender_id.into(),
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
