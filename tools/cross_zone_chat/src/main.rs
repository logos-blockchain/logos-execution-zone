//! Interactive cross-zone chat demo.
//!
//! Boots one Bedrock node hosting two zones (A and B), each running a sequencer
//! whose cross-zone watcher points at the other zone, then serves a local
//! two-column web UI. Type a message in one column and watch it cross Bedrock
//! and appear in the other; two people can chat across the zones.
//!
//! This is the `cross_zone_ping` integration-test topology made interactive:
//! a send builds a `ping_sender::Send` on the sender zone targeting the other
//! zone's `ping_receiver`, the other zone's watcher reads the finalized source
//! block and injects the inbox dispatch, and a per-zone block tailer decodes the
//! delivered `cross_zone_inbox::Dispatch` payloads back into chat text.
//!
//! To make the cross-zone machinery visible, each message is tracked through its
//! pipeline stages and surfaced to the page: submitted into a source block on the
//! sender zone, that block's Bedrock finality (pending -> finalized), and final
//! delivery into a block on the receiver zone. The Bedrock-finality wait is what
//! dominates the latency, so it is shown live.
//!
//! Prerequisite: a working local Docker daemon (Bedrock comes up via
//! `bedrock/docker-compose.yml`). Run with `RISC0_DEV_MODE=1` for fast,
//! proving-free latency; on macOS run under the `just cross-zone-chat` recipe so
//! the DYLD framework shim is set.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unused_async,
    clippy::needless_pass_by_value,
    clippy::infinite_loop,
    reason = "Demo binary: stdout banner is the deliverable; elapsed arithmetic is bounded at chat \
              scale; the per-zone scanners and finality poller are daemon \
              loops that run for the process lifetime; axum handlers must be `async` and take \
              their extractors (State/Json/Query) by value to satisfy the framework's bounds."
)]

use std::{
    collections::BTreeSet,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::Html,
    routing::{get, post},
};
use common::{block::BedrockStatus, transaction::LeeTransaction};
use cross_zone_inbox_core::{CrossZoneConfig, CrossZonePeer, CrossZoneRoute, Instruction, ZoneId};
use cross_zone_outbox_core::outbox_pda;
use lee::{
    Account, ProgramId, PublicTransaction,
    public_transaction::{Message, WitnessSet},
};
use log::{info, warn};
use ping_core::{
    ReceiverInstruction, SenderInstruction, ping_record_pda, receiver_config_account_id,
    sender_config_account_id,
};
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};
use serde::{Deserialize, Serialize};
use test_fixtures::{
    config::{self, SequencerPartialConfig, UrlProtocol, bedrock_channel_id, bedrock_channel_id_b},
    setup::{SequencerSetup, setup_bedrock_node},
};

const HTTP_PORT: u16 = 8088;
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Ordinals probed for a free outbox slot before giving up.
const ORDINAL_PROBE_LIMIT: u32 = 1_024;
/// Transient RPC failures tolerated per probed slot.
const RPC_RETRY_LIMIT: u32 = 5;

/// One chat message tracked through its cross-zone pipeline. Displayed in the
/// receiving zone's column; the stage fields drive the on-page timeline.
struct TrackedMessage {
    id: u64,
    /// Label ("A" / "B") of the sender zone.
    source_label: &'static str,
    /// Label of the receiver zone; the column this message shows in.
    dest_label: &'static str,
    text: String,
    /// Outbox ordinal of this send, used to match the source-zone block.
    ordinal: u32,
    /// Block on the sender zone that included the `ping_sender` tx.
    source_block: Option<u64>,
    /// Whether `source_block` has reached Bedrock finality.
    finalized: bool,
    /// Block on the receiver zone that delivered the inbox dispatch.
    delivered_block: Option<u64>,
    created: Instant,
    /// Wall-clock seconds from submit to delivery, set once delivered.
    delivered_secs: Option<u64>,
}

/// A single send to perform.
#[derive(Deserialize)]
struct SendRequest {
    zone: String,
    text: String,
}

/// The id assigned to a freshly submitted message.
#[derive(Serialize)]
struct SendResponse {
    id: u64,
}

/// One message's current pipeline state, as served to the page.
#[derive(Serialize)]
struct TimelineEntry {
    id: u64,
    /// Receiver column the message belongs to.
    zone: &'static str,
    source_zone: &'static str,
    text: String,
    source_block: Option<u64>,
    finalized: bool,
    delivered_block: Option<u64>,
    /// Seconds elapsed (live until delivered, then frozen at delivery time).
    elapsed: u64,
}

/// Everything one zone needs to send to its peer.
struct ZoneRuntime {
    /// The peer zone's channel id; the target of sends from this zone.
    other_zone: ZoneId,
    client: SequencerClient,
    /// Next outbox ordinal to try for (this zone -> peer).
    ///
    /// An outbox slot is written once and the ordinal names a slot in a space
    /// every user of `ping_sender` shares, so a fixed starting point collides
    /// with whatever the chain already holds. Seeded from a free slot found by
    /// [`next_free_ordinal`], then incremented per send.
    ordinal: AtomicU32,
}

struct AppState {
    zone_a: ZoneRuntime,
    zone_b: ZoneRuntime,
    /// Monotonic id assigned to every message.
    next_id: AtomicU64,
    messages: Mutex<Vec<TrackedMessage>>,
}

impl AppState {
    fn zone(&self, label: &str) -> Option<&ZoneRuntime> {
        match label {
            "A" => Some(&self.zone_a),
            "B" => Some(&self.zone_b),
            _ => None,
        }
    }

    /// Records a freshly submitted outbound message and returns its id.
    fn record_outbound(
        &self,
        source_label: &'static str,
        dest_label: &'static str,
        ordinal: u32,
        text: String,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.messages
            .lock()
            .expect("messages mutex poisoned")
            .push(TrackedMessage {
                id,
                source_label,
                dest_label,
                text,
                ordinal,
                source_block: None,
                finalized: false,
                delivered_block: None,
                created: Instant::now(),
                delivered_secs: None,
            });
        log::info!("[stage] msg {id} submitted {source_label}->{dest_label}");
        id
    }

    /// Marks the source-zone block that included a send, matched by ordinal.
    fn mark_source_block(&self, source_label: &'static str, ordinal: u32, block_id: u64) {
        let mut messages = self.messages.lock().expect("messages mutex poisoned");
        if let Some(message) = messages.iter_mut().find(|m| {
            m.source_label == source_label && m.ordinal == ordinal && m.source_block.is_none()
        }) {
            message.source_block = Some(block_id);
            log::info!(
                "[stage] msg {} in source block {source_label}#{block_id} (+{}s)",
                message.id,
                message.created.elapsed().as_secs()
            );
        }
    }

    /// Marks delivery on the receiver zone. Prefers the oldest undelivered
    /// message whose text matches; falls back to the oldest undelivered for the
    /// zone (delivery order is preserved end to end).
    fn mark_delivered(&self, dest_label: &'static str, text: &str, block_id: u64) {
        let mut messages = self.messages.lock().expect("messages mutex poisoned");
        let undelivered =
            |m: &TrackedMessage| m.dest_label == dest_label && m.delivered_block.is_none();
        let index = messages
            .iter()
            .position(|m| undelivered(m) && m.text == text)
            .or_else(|| messages.iter().position(undelivered));
        if let Some(index) = index {
            let message = &mut messages[index];
            message.delivered_block = Some(block_id);
            let secs = message.created.elapsed().as_secs();
            message.delivered_secs = Some(secs);
            log::info!(
                "[stage] msg {} delivered {dest_label}#{block_id} (+{secs}s total)",
                message.id
            );
        }
    }

    /// Snapshot of (source zone, block) pairs whose finality is still unknown.
    fn pending_finality(&self) -> BTreeSet<(&'static str, u64)> {
        self.messages
            .lock()
            .expect("messages mutex poisoned")
            .iter()
            .filter(|m| !m.finalized)
            .filter_map(|m| m.source_block.map(|block| (m.source_label, block)))
            .collect()
    }

    /// Marks every message whose source block has reached Bedrock finality.
    fn mark_finalized(&self, source_label: &'static str, block_id: u64) {
        for message in self
            .messages
            .lock()
            .expect("messages mutex poisoned")
            .iter_mut()
        {
            if message.source_label == source_label
                && message.source_block == Some(block_id)
                && !message.finalized
            {
                message.finalized = true;
                log::info!(
                    "[stage] msg {} source block {source_label}#{block_id} finalized on Bedrock (+{}s)",
                    message.id,
                    message.created.elapsed().as_secs()
                );
            }
        }
    }

    fn timeline(&self) -> Vec<TimelineEntry> {
        self.messages
            .lock()
            .expect("messages mutex poisoned")
            .iter()
            .map(|m| TimelineEntry {
                id: m.id,
                zone: m.dest_label,
                source_zone: m.source_label,
                text: m.text.clone(),
                source_block: m.source_block,
                finalized: m.finalized,
                delivered_block: m.delivered_block,
                elapsed: m
                    .delivered_secs
                    .unwrap_or_else(|| m.created.elapsed().as_secs()),
            })
            .collect()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Declared first so Bedrock outlives both zones (drops run in reverse order).
    let (_bedrock, bedrock_addr) = setup_bedrock_node()
        .await
        .context("Failed to set up shared Bedrock node")?;

    let channel_a = bedrock_channel_id();
    let channel_b = bedrock_channel_id_b();
    let zone_a: ZoneId = *channel_a.as_ref();
    let zone_b: ZoneId = *channel_b.as_ref();
    let receiver_id = programs::ping_receiver().id();

    // Each zone watches the other and may deliver only to ping_receiver.
    let cross_zone_a = watch_peer(zone_b, receiver_id);
    let cross_zone_b = watch_peer(zone_a, receiver_id);

    let partial = SequencerPartialConfig::default();
    let (seq_a, _home_a) = SequencerSetup::new(partial, bedrock_addr)
        .with_genesis(vec![])
        .with_channel_id(channel_a)
        .with_cross_zone(cross_zone_a)
        .setup()
        .await
        .context("Failed to set up zone A sequencer")?;
    let (seq_b, _home_b) = SequencerSetup::new(partial, bedrock_addr)
        .with_genesis(vec![])
        .with_channel_id(channel_b)
        .with_cross_zone(cross_zone_b)
        .setup()
        .await
        .context("Failed to set up zone B sequencer")?;

    let client_a = sequencer_client(seq_a.addr())?;
    let client_b = sequencer_client(seq_b.addr())?;
    let ordinal_a = next_free_ordinal(&client_a, &zone_b)
        .await
        .context("Failed to find a free outbox ordinal for zone A")?;
    let ordinal_b = next_free_ordinal(&client_b, &zone_a)
        .await
        .context("Failed to find a free outbox ordinal for zone B")?;
    info!("Outbox ordinals start at A={ordinal_a} B={ordinal_b}");

    let state = Arc::new(AppState {
        zone_a: ZoneRuntime {
            other_zone: zone_b,
            client: client_a,
            ordinal: AtomicU32::new(ordinal_a),
        },
        zone_b: ZoneRuntime {
            other_zone: zone_a,
            client: client_b,
            ordinal: AtomicU32::new(ordinal_b),
        },
        next_id: AtomicU64::new(1),
        messages: Mutex::new(Vec::new()),
    });

    tokio::spawn(scan_zone(Arc::clone(&state), "A"));
    tokio::spawn(scan_zone(Arc::clone(&state), "B"));
    tokio::spawn(poll_finality(Arc::clone(&state)));

    let app = Router::new()
        .route("/", get(index))
        .route("/send", post(send_handler))
        .route("/timeline", get(timeline_handler))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], HTTP_PORT));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind {addr}"))?;

    println!("\n  💬 Cross-zone chat ready — open http://127.0.0.1:{HTTP_PORT} in your browser\n");

    axum::serve(listener, app)
        .await
        .context("HTTP server error")?;
    Ok(())
}

/// A cross-zone config whose single peer is `peer`, allowed to deliver only to
/// `receiver_id`.
fn watch_peer(peer: ZoneId, receiver_id: ProgramId) -> CrossZoneConfig {
    CrossZoneConfig {
        peers: vec![CrossZonePeer {
            channel_id: peer,
            allowed_routes: vec![CrossZoneRoute {
                src_program_id: programs::ping_sender().id(),
                target_program_id: receiver_id,
                mint_cap: None,
            }],
            expected_block_signing_pubkeys: Vec::new(),
        }],
        source_authority: None,
        source_governance: None,
    }
}

fn sequencer_client(addr: SocketAddr) -> Result<SequencerClient> {
    let url =
        config::addr_to_url(UrlProtocol::Http, addr).context("Failed to build sequencer URL")?;
    SequencerClientBuilder::default()
        .build(url)
        .context("Failed to build sequencer client")
}

/// A free outbox slot for this zone's `ping_sender` to start counting from: the
/// first unwritten one at or after a random ordinal.
///
/// An outbox slot is written once, so a send into an occupied one fails at block
/// production, and `send_transaction` checks a transaction only statelessly, so
/// nothing tells the sender. The predicate here is the one the guest asserts,
/// asked before submitting instead of after.
///
/// Random rather than zero because the ordinal space is shared by every user of
/// `ping_sender` and a slot costs one unsigned transaction to occupy, so any
/// fixed starting point can be squatted. On a chain this process owns, which is
/// what `just cross-zone-chat` boots, nothing is occupied and this returns on
/// its first try; it earns its keep against a chain the tool did not create.
///
/// It only places the first send. Later ordinals come from incrementing, so a
/// slot taken after this returns still collides, at a probability of the
/// occupied count over 2^32.
async fn next_free_ordinal(client: &SequencerClient, target_zone: &ZoneId) -> Result<u32> {
    let outbox_id = programs::cross_zone_outbox().id();
    let emitter = programs::ping_sender().id();
    let start: u32 = rand::random();

    for offset in 0..ORDINAL_PROBE_LIMIT {
        let ordinal = start.wrapping_add(offset);
        let slot = outbox_pda(outbox_id, emitter, target_zone, ordinal);
        // Retried rather than propagated: by here the run has already paid for a
        // Bedrock bring-up and two sequencer boots, and every other RPC caller
        // in this tool rides out a transient error rather than ending the run.
        let mut attempt = 0_u32;
        let account = loop {
            match client.get_account(slot).await {
                Ok(account) => break account,
                Err(err) if attempt < RPC_RETRY_LIMIT => {
                    attempt += 1;
                    warn!("Outbox probe failed, retrying ({attempt}/{RPC_RETRY_LIMIT}): {err}");
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
                Err(err) => {
                    return Err(err).context("Failed to read an outbox slot while probing");
                }
            }
        };
        if account == Account::default() {
            return Ok(ordinal);
        }
    }
    anyhow::bail!("No free outbox ordinal in {ORDINAL_PROBE_LIMIT} tried from {start}")
}

/// Scans one zone's new blocks. A `ping_sender` tx marks the message's source
/// block (its outbound leg); an inbox dispatch marks delivery on this zone.
/// Runs forever; transient RPC errors are logged and retried.
async fn scan_zone(state: Arc<AppState>, label: &'static str) {
    let inbox_id = programs::cross_zone_inbox().id();
    let sender_id = programs::ping_sender().id();
    let client = &state.zone(label).expect("zone runtime exists").client;

    // Start from the current tip so genesis/boot blocks are skipped.
    let mut cursor = client.get_last_block_id().await.unwrap_or(0);

    loop {
        tokio::time::sleep(POLL_INTERVAL).await;

        let last = match client.get_last_block_id().await {
            Ok(last) => last,
            Err(err) => {
                warn!("[{label}] get_last_block_id failed: {err:#}");
                continue;
            }
        };

        while cursor < last {
            let next = cursor.saturating_add(1);
            match client.get_block(next).await {
                Ok(Some(block)) => {
                    for tx in &block.body.transactions {
                        let LeeTransaction::Public(public) = tx else {
                            continue;
                        };
                        let program_id = public.message.program_id;
                        let data = &public.message.instruction_data;
                        // A tx targets at most one of these programs; check both
                        // independently rather than chaining (avoids an empty else).
                        if program_id == inbox_id
                            && let Some(text) = decode_inbox_text(data)
                        {
                            state.mark_delivered(label, &text, next);
                        }
                        if program_id == sender_id
                            && let Some(ordinal) = decode_send_ordinal(data)
                        {
                            state.mark_source_block(label, ordinal, next);
                        }
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    warn!("[{label}] get_block({next}) failed: {err:#}");
                    break;
                }
            }
            cursor = next;
        }
    }
}

/// Polls each tracked source block's Bedrock finality until it is finalized.
async fn poll_finality(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        for (label, block_id) in state.pending_finality() {
            let client = &state.zone(label).expect("zone runtime exists").client;
            match client.get_block(block_id).await {
                Ok(Some(block)) => {
                    if matches!(block.bedrock_status, BedrockStatus::Finalized) {
                        state.mark_finalized(label, block_id);
                    }
                }
                Ok(None) => {}
                Err(err) => warn!("[{label}] finality get_block({block_id}) failed: {err:#}"),
            }
        }
    }
}

/// Recovers the chat text from an inbox dispatch tx's instruction data.
fn decode_inbox_text(instruction_data: &[u8]) -> Option<String> {
    let instruction: Instruction = borsh::from_slice::<Instruction>(instruction_data).ok()?;
    let Instruction::Dispatch(message) = instruction else {
        return None;
    };
    decode_payload(&message.payload)
}

/// Recovers the outbox ordinal from a `ping_sender::Send` tx's instruction data.
fn decode_send_ordinal(instruction_data: &[u8]) -> Option<u32> {
    let instruction: SenderInstruction =
        borsh::from_slice::<SenderInstruction>(instruction_data).ok()?;
    let SenderInstruction::Send { ordinal, .. } = instruction else {
        return None;
    };
    Some(ordinal)
}

/// Decodes a `ping_receiver::Record` payload (borsh bytes) to text.
fn decode_payload(payload: &[u8]) -> Option<String> {
    let instruction: ReceiverInstruction =
        borsh::from_slice::<ReceiverInstruction>(payload).ok()?;
    let ReceiverInstruction::Record { payload: bytes } = instruction else {
        return None;
    };
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Builds the unsigned `ping_sender::Send` that carries `text` to `other_zone`,
/// mirroring `integration_tests/tests/cross_zone_ping.rs`.
fn build_send_tx(other_zone: ZoneId, ordinal: u32, text: &str) -> LeeTransaction {
    let receiver_id = programs::ping_receiver().id();
    let outbox_id = programs::cross_zone_outbox().id();

    let payload = borsh::to_vec(&ReceiverInstruction::Record {
        payload: text.as_bytes().to_vec(),
    })
    .expect("serialize record instruction");

    let send = SenderInstruction::Send {
        target_zone: other_zone,
        target_program_id: receiver_id,
        target_accounts: vec![
            receiver_config_account_id(receiver_id).into_value(),
            ping_record_pda(receiver_id).into_value(),
        ],
        payload,
        ordinal,
    };

    let sender_id = programs::ping_sender().id();
    let outbox_account = outbox_pda(outbox_id, sender_id, &other_zone, ordinal);
    let message = Message::try_new(
        sender_id,
        vec![sender_config_account_id(sender_id), outbox_account],
        vec![],
        send,
    )
    .expect("build ping_sender message");

    LeeTransaction::Public(PublicTransaction::new(
        message,
        WitnessSet::from_raw_parts(vec![]),
    ))
}

async fn index() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

async fn send_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SendRequest>,
) -> Result<Json<SendResponse>, (StatusCode, String)> {
    let text = request.text.trim();
    if text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "empty message".to_owned()));
    }
    let (source_label, dest_label) = match request.zone.as_str() {
        "A" => ("A", "B"),
        "B" => ("B", "A"),
        other => return Err((StatusCode::BAD_REQUEST, format!("unknown zone {other}"))),
    };
    let zone = state.zone(source_label).expect("zone runtime exists");

    let ordinal = zone.ordinal.fetch_add(1, Ordering::SeqCst);
    let tx = build_send_tx(zone.other_zone, ordinal, text);
    let id = state.record_outbound(source_label, dest_label, ordinal, text.to_owned());
    zone.client
        .send_transaction(tx)
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, format!("submit failed: {err:#}")))?;
    Ok(Json(SendResponse { id }))
}

async fn timeline_handler(State(state): State<Arc<AppState>>) -> Json<Vec<TimelineEntry>> {
    Json(state.timeline())
}
