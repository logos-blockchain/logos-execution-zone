use std::time::Duration;

use anyhow::{Context as _, Result};
use chain_state::consistency::checkpoint_eq_opt;
use common::{
    HashType,
    block::{Block, PeerChainTip},
    transaction::LeeTransaction,
};
use cross_zone::{
    EmissionSource, Link, StallState, build_dispatch_from_emission, equivocation_report,
    extract_emission, is_sequencer_only_program, link_to_tip, screen_peer_block,
};
use cross_zone_inbox_core::message_key;
use futures::{Stream, StreamExt as _};
use kameo::actor::ActorRef;
use lee::PublicKey;
use log::{debug, error, warn};
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use logos_blockchain_zone_sdk::{
    CommonHttpClient, Slot, ZoneMessage, adapter::NodeHttpClient, sequencer::SequencerCheckpoint,
};
use sequencer_storage_actor::{
    StorageActorTrait,
    protocol::{
        AddPendingCrossZoneDispatches, DeleteCrossZonePeerFloor, GetCrossZonePeerFloorBytes,
        GetCrossZonePeerTip, PeerZoneKey, PendingCrossZoneDispatchRecord,
        SetCrossZonePeerFloorBytes, SetCrossZonePeerTip,
    },
};

use crate::{
    config::{BedrockConfig, CrossZoneConfig},
    task_group::TaskGroup,
};

/// Consecutive passes a watcher spends stuck on one slot before it says so as
/// something more than the per-pass failure.
///
/// One pass per poll interval, which is the block time, so this is minutes of
/// retrying rather than seconds. A transient failure (a truncated read, a peer
/// mid-upgrade) heals well inside that; anything still stuck after it wants
/// someone to look.
const STUCK_SLOT_ALERT_PASSES: u32 = 20;

/// An indexer context for spawning.
struct IndexerContext {
    channel_id: ChannelId,
    node: NodeHttpClient,
}

impl IndexerContext {
    const fn new(channel_id: ChannelId, node: NodeHttpClient) -> Self {
        Self { channel_id, node }
    }
}

/// The per-peer settings one watcher pass needs.
struct PeerContext {
    peer_zone: [u8; 32],
    self_zone: [u8; 32],
    expected_pubkey: Option<PublicKey>,
}

/// Why one pass over a peer's stream ended.
///
/// All of them hold the delivery floor at the last slot the watcher consumed
/// whole, bar [`PassOutcome::Drained`] and [`PassOutcome::Stranded`], so the
/// next pass re-reads from there. Only a block that will not deserialize ends a
/// pass; [`link_to_tip`] says why one that decodes never does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PassOutcome {
    /// The stream drained, having delivered from at least one block or found
    /// nothing to place.
    Drained,
    /// The stream drained having placed nothing, while passing over blocks that
    /// were not on the chain this watcher follows.
    ///
    /// The shape of a tip that no longer tracks the peer: every later block sits
    /// above it, is read past, and the floor moves over it, so the peer goes
    /// quiet with nothing else to show for it. One pass of this is ordinary (a
    /// peer inscribing something that is not its next block), so it is counted
    /// rather than acted on.
    Stranded,
    /// Ended inside this slot: its block would not deserialize.
    Undecodable(Slot),
    /// Ended inside this slot: a delivery could not be recorded, or the chain
    /// tip covering it could not be stored.
    Undelivered(Slot),
}

/// The pass-to-pass state of one watcher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct WatcherState {
    stall: StallState<Slot>,
    /// Consecutive passes that placed nothing while skipping blocks. Not keyed
    /// by slot: the peer keeps producing, so every such pass ends at a new slot
    /// and a slot-keyed count would reset to one for ever.
    stranded: u32,
}

impl WatcherState {
    /// Folds one pass's outcome into the stall and stranded counts, returning
    /// the slot the watcher is stuck on and how long it has been stuck.
    fn after_pass(&mut self, outcome: PassOutcome, cursor: Option<Slot>) -> Option<(Slot, u32)> {
        match outcome {
            PassOutcome::Stranded => self.stranded = self.stranded.saturating_add(1),
            PassOutcome::Drained => self.stranded = 0,
            PassOutcome::Undecodable(_) | PassOutcome::Undelivered(_) => {}
        }
        let stuck_on = match outcome {
            PassOutcome::Undecodable(slot) | PassOutcome::Undelivered(slot) => Some(slot),
            PassOutcome::Drained | PassOutcome::Stranded => None,
        };
        self.stall.after_pass(stuck_on, cursor)
    }
}

/// What a starting watcher does with its stored floor and chain tip.
#[derive(Debug)]
struct Resume {
    /// Where to read from. `None` is the peer's genesis.
    cursor: Option<SequencerCheckpoint>,
    /// Whether the stored floor has to be dropped before anything is read.
    clear_floor: bool,
}

impl core::cmp::PartialEq for Resume {
    fn eq(&self, other: &Self) -> bool {
        (self.clear_floor == other.clear_floor)
            && checkpoint_eq_opt(self.cursor.as_ref(), other.cursor.as_ref())
    }
}

impl core::cmp::Eq for Resume {}

/// Whether a watcher stuck for `attempts` passes should say so on this one.
///
/// Every [`STUCK_SLOT_ALERT_PASSES`], not on the crossing alone: a stall that
/// never clears would otherwise be reported once and then look resolved for as
/// long as it lasts. Not every pass, since that is one line per block time.
const fn alerts_at(attempts: u32) -> bool {
    attempts > 0 && attempts.is_multiple_of(STUCK_SLOT_ALERT_PASSES)
}

/// Where a starting watcher resumes reading a peer's channel.
///
/// A store holding a floor but no tip predates chain pinning, and its next block
/// would arrive mid-chain with nothing to link against, so it re-reads from the
/// peer's genesis to rebuild the tip. Nothing is delivered twice for that, but
/// every delivery is re-offered to the pending list, a scan and a full rewrite
/// per peer block: a peer with a long history pays for it once.
///
/// The floor is dropped rather than ignored, or a crash partway through the
/// rebuild resumes above the tip it had just started building.
fn resume_from(tip: Option<PeerChainTip>, floor: Option<SequencerCheckpoint>) -> Resume {
    match tip {
        Some(_) => Resume {
            cursor: floor,
            clear_floor: false,
        },
        None => Resume {
            cursor: None,
            clear_floor: floor.is_some(),
        },
    }
}

/// This watcher's delivery floor on `peer_zone`'s channel.
///
/// The highest slot every message of which was delivered, or `None` before it
/// has delivered anything from that peer. Stored as a little-endian `u64`, which
/// is why the encoding lives here rather than in the storage actor.
async fn get_cross_zone_peer_floor<S: StorageActorTrait>(
    storage_ref: &ActorRef<S>,
    peer_zone: PeerZoneKey,
) -> Result<Option<SequencerCheckpoint>> {
    let Some(bytes) = storage_ref
        .ask(GetCrossZonePeerFloorBytes { peer_zone })
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(
        serde_json::from_slice(&bytes).context("Checkpoint must deserialize")?,
    ))
}

async fn set_cross_zone_peer_floor<S: StorageActorTrait>(
    storage_ref: &ActorRef<S>,
    peer_zone: PeerZoneKey,
    floor: SequencerCheckpoint,
) -> Result<()> {
    storage_ref
        .ask(SetCrossZonePeerFloorBytes {
            peer_zone,
            bytes: serde_json::to_vec(&floor).context("Checkpoint must serialize")?,
        })
        .await?;
    Ok(())
}

/// Drops the stored floor so the watcher reads `peer_zone`'s channel from the
/// peer's genesis again.
async fn clear_cross_zone_peer_floor<S: StorageActorTrait>(
    storage_ref: &ActorRef<S>,
    peer_zone: PeerZoneKey,
) -> Result<()> {
    storage_ref
        .ask(DeleteCrossZonePeerFloor { peer_zone })
        .await?;
    Ok(())
}

/// Spawns one watcher task per configured peer.
///
/// Each task reads the peer's finalized blocks from Bedrock, recognizes outbound
/// messages addressed to this zone, and records the matching inbox dispatch in
/// the store. Delivering it is block production's job, which drains those
/// records every turn.
///
/// The returned group must be kept alive for as long as the watchers should
/// run; dropping it stops them, and awaiting
/// [`TaskGroup::shutdown`](crate::task_group::TaskGroup::shutdown) is what
/// proves they have stopped.
#[must_use]
pub fn spawn_watchers<S: StorageActorTrait>(
    bedrock_config: &BedrockConfig,
    cross_zone: &CrossZoneConfig,
    poll_interval: Duration,
    storage_ref: &ActorRef<S>,
) -> TaskGroup {
    let self_zone: [u8; 32] = *bedrock_config.channel_id.as_ref();
    let mut tasks = Vec::new();

    for peer in cross_zone.peers.clone() {
        let node = NodeHttpClient::new(
            CommonHttpClient::new(bedrock_config.auth.clone().map(Into::into)),
            bedrock_config.node_url.clone(),
        );
        let expected_pubkey = peer.expected_block_signing_pubkey.map(|bytes| {
            PublicKey::try_new(bytes).expect("configured peer block-signing pubkey is a valid key")
        });
        tasks.push(tokio::spawn(watch_peer(
            IndexerContext::new(ChannelId::from(peer.channel_id), node),
            PeerContext {
                peer_zone: peer.channel_id,
                self_zone,
                expected_pubkey,
            },
            poll_interval,
            storage_ref.clone(),
        )));
    }

    TaskGroup::new(tasks)
}

#[expect(
    clippy::infinite_loop,
    reason = "the peer watcher runs for the lifetime of the sequencer process"
)]
async fn watch_peer<S: StorageActorTrait>(
    zone_indexer_context: IndexerContext,
    peer: PeerContext,
    poll_interval: Duration,
    storage_ref: ActorRef<S>,
) {
    let peer_zone = peer.peer_zone;
    log::info!(
        "Cross-zone watcher started for peer {}",
        hex::encode(peer_zone)
    );

    // Resume from the delivery floor: the highest slot every message of which
    // was decoded and recorded. Re-reading a peer channel is safe (the dispatch
    // key is content-addressed and the inbox no-ops a replay) but re-records
    // every already-delivered message, so without this a restart replayed the
    // peer's whole history into the store.
    let floor = match get_cross_zone_peer_floor(&storage_ref, peer_zone).await {
        Ok(floor) => floor,
        Err(err) => {
            // Falling back to `None` would re-read the peer's whole history and
            // re-inject every message it ever delivered. Stopping is the smaller
            // failure, and a stopped watcher shows up as unhealthy.
            error!(
                "Watcher failed to load the stored delivery floor for peer {}: {err:#}. Stopping this watcher rather than re-reading the channel from the beginning.",
                hex::encode(peer_zone)
            );
            return;
        }
    };
    // The chain this watcher has already delivered from. Without it no block can
    // be told apart from one claiming an id it never reached, so a watcher that
    // cannot read it delivers nothing rather than guessing.
    let mut tip = match storage_ref.ask(GetCrossZonePeerTip { peer_zone }).await {
        Ok(tip) => tip,
        Err(err) => {
            error!(
                "Watcher failed to load the stored chain tip for peer {}: {err:#}. Stopping this watcher rather than accepting blocks with nothing to link them against.",
                hex::encode(peer_zone)
            );
            return;
        }
    };
    let resume = resume_from(tip, floor);
    if resume.clear_floor {
        error!(
            "Watcher for peer {} holds a delivery floor but no chain tip, so it cannot tell which block continues that peer's chain. Re-reading the channel from the peer's genesis block; deliveries already recorded are deduplicated by message key.",
            hex::encode(peer_zone)
        );
        // Durably, before reading anything, or a crash partway through the
        // rebuild resumes from the stale floor with nothing able to link.
        if let Err(err) = clear_cross_zone_peer_floor(&storage_ref, peer_zone).await {
            error!(
                "Watcher could not clear the stale delivery floor for peer {}: {err:#}. Stopping this watcher rather than rebuilding its chain against a floor a restart would resume from.",
                hex::encode(peer_zone)
            );
            return;
        }
    }
    let mut cursor = resume.cursor;
    if let Some(checkpoint) = &cursor {
        log::info!(
            "Resuming watcher for peer {} from checkpoint {checkpoint:?}",
            hex::encode(peer_zone)
        );
    }

    // In memory, and rebuilt from the store on every start: it says only how
    // loud to be about a slot this watcher is stuck on.
    let mut state = WatcherState::default();
    loop {
        let stream = chain_state::consistency::next_messages_own(
            zone_indexer_context.node.clone(),
            zone_indexer_context.channel_id,
            cursor.clone(),
        );
        let outcome = consume_peer_stream(stream, &peer, &storage_ref, &mut cursor, &mut tip).await;

        if let Some((slot, attempts)) =
            state.after_pass(outcome, cursor.as_ref().map(|c| c.lib_slot))
            && alerts_at(attempts)
        {
            error!(
                "Watcher for peer {} has been stuck at slot {slot:?} for {attempts} passes. Nothing from that peer is being delivered until it clears, and the delivery floor stays at {:?} so the slot keeps coming back.",
                hex::encode(peer_zone),
                get_cross_zone_peer_floor(&storage_ref, peer_zone)
                    .await
                    .ok()
                    .flatten()
            );
        }
        // Reads on rather than stopping, since one such pass is ordinary, but a
        // run of them means the stored tip no longer tracks this peer and every
        // block since has been passed over. The floor has moved with them, so
        // this does not clear on its own.
        if alerts_at(state.stranded) {
            error!(
                "Watcher for peer {} has read {} consecutive passes without placing a block on the chain it has delivered from, tip {:?}. Nothing from that peer is being delivered, and the blocks passed over are already below the delivery floor.",
                hex::encode(peer_zone),
                state.stranded,
                tip.map(|held| held.block_id)
            );
        }

        // Stream ended (caught up to the peer's last finalized block); poll again.
        tokio::time::sleep(poll_interval).await;
    }
}

/// Delivers the peer blocks carried by `stream`, moving `cursor` as it goes,
/// persisting the delivery floor behind it and the chain tip as it accepts each
/// block. Says why the pass ended.
///
/// Ending early holds the floor at the last slot consumed whole, so the next
/// poll re-reads from there and a transient failure heals.
async fn consume_peer_stream<Str, S: StorageActorTrait>(
    stream: Str,
    peer: &PeerContext,
    storage_ref: &ActorRef<S>,
    cursor: &mut Option<SequencerCheckpoint>,
    tip: &mut Option<PeerChainTip>,
) -> PassOutcome
where
    Str: Stream<Item = (ZoneMessage, SequencerCheckpoint)>,
{
    let mut stream = std::pin::pin!(stream);
    // The slot being consumed: every message of it seen so far is handled, but
    // there may be more to come, so the cursor may not advance onto it yet.
    let mut in_progress: Option<SequencerCheckpoint> = None;
    // What the pass did with the blocks it read, so a peer going quiet behind a
    // tip that no longer tracks it is distinguishable from one with nothing to
    // say.
    let mut placed = 0_usize;
    let mut skipped = 0_usize;

    while let Some((msg, checkpoint)) = stream.next().await {
        let slot = checkpoint.lib_slot;

        if !checkpoint_eq_opt(in_progress.as_ref(), Some(&checkpoint)) {
            // A message from a later slot means the previous one completed.
            if let Some(done) = in_progress {
                advance_cursor(storage_ref, peer.peer_zone, cursor, done).await;
            }
            in_progress = Some(checkpoint);
        }

        let zone_block = match msg {
            ZoneMessage::Block(block) => block,
            ZoneMessage::Deposit(_) | ZoneMessage::Withdraw(_) => continue,
        };
        match borsh::from_slice::<Block>(&zone_block.data) {
            Ok(block) => {
                debug!(
                    "Watcher observed finalized peer {} block {}",
                    hex::encode(peer.peer_zone),
                    block.header.block_id
                );
                // Nothing but [`Link::Next`] is ever delivered from, and
                // nothing but a block that will not decode stops the pass. A
                // peer can inscribe anything it likes on its own channel, so a
                // block this watcher cannot place is read past rather than
                // treated as the end of the chain: the peer's own next honest
                // block still links to the tip.
                let link = match screen_peer_block(&block, peer.expected_pubkey.as_ref()) {
                    Ok(recomputed) => link_to_tip(tip.as_ref(), &block, recomputed),
                    Err(refusal) => {
                        skipped = skipped.saturating_add(1);
                        warn!(
                            "Watcher not delivering from peer {} block at slot {slot:?}: {refusal}. Reading on; the peer's next block that continues the chain still delivers.",
                            hex::encode(peer.peer_zone)
                        );
                        continue;
                    }
                };
                match link {
                    Link::AlreadySeen { equivocates } => {
                        if equivocates && let Some(held) = *tip {
                            error!(
                                "{}",
                                equivocation_report(
                                    &peer.peer_zone,
                                    block.header.block_id,
                                    held.block_hash,
                                    block.header.hash
                                )
                            );
                        } else {
                            debug!(
                                "Watcher ignoring peer {} block {}: at or below the block it has already delivered from",
                                hex::encode(peer.peer_zone),
                                block.header.block_id
                            );
                        }
                    }
                    Link::OffChain(reason) => {
                        skipped = skipped.saturating_add(1);
                        warn!(
                            "Watcher not delivering from peer {} block at slot {slot:?}: {reason}. Reading on; the peer's next block that continues the chain still delivers.",
                            hex::encode(peer.peer_zone)
                        );
                    }
                    Link::Next(block_hash) => {
                        if !record_block_deliveries(&block, block_hash, peer, storage_ref).await {
                            // Recording a delivery is what makes it survive the
                            // mempool. Letting the pass finish here would move
                            // the floor past this slot on a store that just
                            // refused the write, and nothing re-reads a slot
                            // below the floor.
                            error!(
                                "Watcher could not record every delivery in peer {} block {}. Holding the floor and retrying the slot.",
                                hex::encode(peer.peer_zone),
                                block.header.block_id
                            );
                            return PassOutcome::Undelivered(slot);
                        }
                        // After the deliveries, never before: a tip past
                        // deliveries that were never recorded makes the blocks
                        // carrying them read as already seen, and nothing looks
                        // at them again.
                        let next = PeerChainTip {
                            block_id: block.header.block_id,
                            block_hash,
                        };
                        if let Err(err) = storage_ref
                            .ask(SetCrossZonePeerTip {
                                peer_zone: peer.peer_zone,
                                tip: next,
                            })
                            .await
                        {
                            // Advancing only in memory would leave a restart
                            // resuming from a floor above a tip, and every block
                            // after it unlinkable.
                            error!(
                                "Watcher could not store the chain tip for peer {} at block {}: {err:#}. Holding the floor and retrying the slot.",
                                hex::encode(peer.peer_zone),
                                block.header.block_id
                            );
                            return PassOutcome::Undelivered(slot);
                        }
                        *tip = Some(next);
                        placed = placed.saturating_add(1);
                    }
                }
            }
            Err(err) => {
                warn!(
                    "Watcher failed to deserialize peer {} block at slot {slot:?}: {err}. Holding the cursor and retrying.",
                    hex::encode(peer.peer_zone)
                );
                return PassOutcome::Undecodable(slot);
            }
        }
    }

    // The stream drained cleanly, so the slot in progress completed too.
    if let Some(done) = in_progress {
        advance_cursor(storage_ref, peer.peer_zone, cursor, done).await;
    }
    if placed == 0 && skipped > 0 {
        return PassOutcome::Stranded;
    }
    PassOutcome::Drained
}

/// Moves the in-memory read cursor past `slot` and the durable delivery floor
/// with it.
///
/// A persist failure is only logged: the worst case is re-reading from the last
/// stored slot after a restart, which delivery handles idempotently.
async fn advance_cursor<S: StorageActorTrait>(
    storage_ref: &ActorRef<S>,
    peer_zone: [u8; 32],
    cursor: &mut Option<SequencerCheckpoint>,
    checkpoint: SequencerCheckpoint,
) {
    *cursor = Some(checkpoint.clone());
    if let Err(err) = set_cross_zone_peer_floor(storage_ref, peer_zone, checkpoint).await {
        warn!(
            "Failed to persist watcher delivery floor for peer {}: {err:#}",
            hex::encode(peer_zone)
        );
    }
}

/// Scans one peer block for outbound messages and records a dispatch per match.
///
/// Returns `false` if a delivery could not be recorded, which the caller turns
/// into a stall: the record is the only thing standing between a durable read
/// position and a lost message.
///
/// `block_hash` is the value [`screen_peer_block`] recomputed from the block's
/// own contents, not `block.header.hash`, which the signature does not cover.
async fn record_block_deliveries<S: StorageActorTrait>(
    block: &Block,
    block_hash: HashType,
    peer: &PeerContext,
    storage_ref: &ActorRef<S>,
) -> bool {
    let peer_zone = peer.peer_zone;
    let self_zone = peer.self_zone;
    // Collected and written once, so recording a block is all-or-nothing; see
    // RocksDBIO::add_pending_cross_zone_dispatches.
    let mut deliveries = Vec::new();
    for (index, tx) in block.body.transactions.iter().enumerate() {
        let LeeTransaction::Public(public_tx) = tx else {
            continue;
        };
        let message = public_tx.message();
        let Some(emission) = extract_emission(message.program_id, &message.instruction_data) else {
            continue;
        };

        if emission.target_zone != self_zone {
            continue;
        }
        // Targets authorize their own sources now, so this is not authorization,
        // it is hygiene: a delivery the zone will certainly refuse still costs a
        // pending-list slot and three execution attempts before it is dead
        // lettered. Kept host-side only, never in `extract_emission` or the
        // verifier's re-derivation, where a check that depends on this build would
        // make the two disagree and halt ingestion.
        if is_sequencer_only_program(emission.target_program_id) {
            warn!(
                "Watcher dropping message from peer {}: a peer may not dispatch into a sequencer-only program",
                hex::encode(peer_zone)
            );
            continue;
        }

        let src_tx_index = u32::try_from(index).unwrap_or(u32::MAX);
        let dispatch = build_dispatch_from_emission(
            &EmissionSource {
                src_zone: peer_zone,
                src_block_id: block.header.block_id,
                src_block_hash: block_hash.0,
                src_tx_index,
                src_program_id: message.program_id,
            },
            emission.target_program_id,
            &emission.target_accounts,
            emission.payload,
        );
        let dispatch = LeeTransaction::Public(dispatch);

        // Recording is the delivery. The floor is durable, so once it advances
        // this peer block is never re-read; the record is what block production
        // drains on its next turn, and what a restart still has. It is dropped
        // when the delivery itself becomes irreversible.
        let key = message_key(&peer_zone, block.header.block_id, src_tx_index);
        let encoded = match borsh::to_vec(&dispatch) {
            Ok(encoded) => encoded,
            Err(err) => {
                error!(
                    "Failed to encode cross-zone dispatch {}: {err}",
                    hex::encode(key)
                );
                return false;
            }
        };
        deliveries.push(PendingCrossZoneDispatchRecord::recorded(key, encoded));
    }

    let offered = deliveries.len();
    match storage_ref
        .ask(AddPendingCrossZoneDispatches {
            dispatches: deliveries,
        })
        .await
    {
        // Fewer accepted than offered means the rest were recorded by an earlier
        // pass over the same slot, which the retry loop repeats for as long as
        // the slot stays stuck.
        Ok(accepted) => {
            if accepted > 0 {
                log::info!(
                    "Watcher recorded {accepted} of {offered} cross-zone deliveries from peer {} block {}",
                    hex::encode(peer_zone),
                    block.header.block_id
                );
            } else {
                debug!(
                    "Watcher already held every cross-zone delivery in peer {} block {}",
                    hex::encode(peer_zone),
                    block.header.block_id
                );
            }
            true
        }
        // Includes the pending list being full, which is why this holds the
        // floor rather than dropping the block: the slot stays re-readable and
        // the peer's messages wait instead of being lost.
        Err(err) => {
            error!(
                "Failed to record the {offered} cross-zone deliveries in peer {} block {}: {err}",
                hex::encode(peer_zone),
                block.header.block_id
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use common::test_utils::produce_dummy_block;
    use cross_zone::test_utils::{linked_chain_to, ping_emission};
    use futures::stream;
    use kameo::actor::Spawn as _;
    use logos_blockchain_core::mantle::ops::channel::{MsgId, inscribe::Inscription};
    use logos_blockchain_zone_sdk::ZoneBlock;
    use sequencer_storage_actor::{
        StorageActor,
        mock::MockStorageActor,
        protocol::{GetPendingCrossZoneDispatches, RecordNewBlock},
    };
    use tempfile::TempDir;

    use super::*;

    const SELF_ZONE: [u8; 32] = [1; 32];
    const PEER_ZONE: [u8; 32] = [2; 32];

    fn peer_context() -> PeerContext {
        PeerContext {
            peer_zone: PEER_ZONE,
            self_zone: SELF_ZONE,
            expected_pubkey: None,
        }
    }

    /// A store backed by a temp dir. The dir is returned so it outlives the db.
    async fn store() -> (TempDir, ActorRef<StorageActor>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let storage_ref = StorageActor::spawn(StorageActor::new(dir.path()).expect("open storage"));
        seed_genesis(&storage_ref).await;
        (dir, storage_ref)
    }

    /// The watcher's messages need a database, not a chain, but the peer-tip
    /// and dispatch cells share a store with one — so seed it like a real node.
    async fn seed_genesis(storage_ref: &ActorRef<StorageActor>) {
        storage_ref
            .ask(RecordNewBlock {
                block: produce_dummy_block(0, None, vec![]),
                withdrawals: vec![],
                state: Arc::new(lee::V03State::new()),
                checkpoint_bytes: None,
            })
            .await
            .expect("seed genesis");
    }

    /// A `ping_sender` emission addressed to `SELF_ZONE`.
    fn emission() -> LeeTransaction {
        emission_to(programs::ping_receiver().id())
    }

    /// A `ping_sender` emission aimed at `target_program_id`.
    fn emission_to(target_program_id: lee_core::program::ProgramId) -> LeeTransaction {
        ping_emission(SELF_ZONE, target_program_id, b"hi")
    }

    fn peer_msg(data: Vec<u8>, slot: u64) -> (ZoneMessage, SequencerCheckpoint) {
        (
            ZoneMessage::Block(ZoneBlock {
                id: MsgId::from([0; 32]),
                data: Inscription::try_from(data).expect("test inscription is within bounds"),
            }),
            checkpoint(slot),
        )
    }

    /// The peer's chain from its genesis up to and including `block_id`, each
    /// block linked to the one before it and carrying one emission for this
    /// zone.
    fn chain_to(block_id: u64) -> Vec<Block> {
        linked_chain_to(block_id, |_| vec![emission()])
    }

    /// The peer's block at `block_id`.
    fn chain_block(block_id: u64) -> Block {
        chain_to(block_id).pop().expect("chain reaches block_id")
    }

    /// The hash the block after `block_id` has to link to.
    fn chain_hash(block_id: u64) -> HashType {
        chain_block(block_id).header.hash
    }

    /// A block continuing the peer's chain at `block_id`, whose one emission
    /// targets `target_program_id`.
    fn chain_block_to(block_id: u64, target_program_id: lee_core::program::ProgramId) -> Block {
        let prefix = chain_to(block_id.saturating_sub(1));
        produce_dummy_block(
            block_id,
            prefix.last().map(|block| block.header.hash),
            vec![emission_to(target_program_id)],
        )
    }

    fn block_msg(block: &Block, slot: u64) -> (ZoneMessage, SequencerCheckpoint) {
        peer_msg(borsh::to_vec(block).expect("block serializes"), slot)
    }

    /// A stream item carrying the peer's block `block_id`.
    fn peer_block_msg(block_id: u64, slot: u64) -> (ZoneMessage, SequencerCheckpoint) {
        block_msg(&chain_block(block_id), slot)
    }

    /// A stream item carrying a block whose one emission targets
    /// `target_program_id`.
    fn peer_block_msg_to(
        block_id: u64,
        slot: u64,
        target_program_id: lee_core::program::ProgramId,
    ) -> (ZoneMessage, SequencerCheckpoint) {
        block_msg(&chain_block_to(block_id, target_program_id), slot)
    }

    /// The tip a watcher holds after delivering up to `block_id`.
    fn tip_at(block_id: u64) -> PeerChainTip {
        PeerChainTip {
            block_id,
            block_hash: chain_hash(block_id),
        }
    }

    fn undecodable_msg(slot: u64) -> (ZoneMessage, SequencerCheckpoint) {
        peer_msg(b"not a block".to_vec(), slot)
    }

    fn checkpoint(slot: u64) -> SequencerCheckpoint {
        SequencerCheckpoint {
            last_msg_id: MsgId::from([0; 32]),
            pending_txs: vec![],
            lib: [42; 32].into(),
            lib_slot: Slot::from(slot),
        }
    }

    /// The message keys recorded so far, sorted: the store keys each record by
    /// its message key, so no insertion order survives.
    async fn recorded_keys(storage_ref: &ActorRef<StorageActor>) -> Vec<[u8; 32]> {
        let mut keys = storage_ref
            .ask(GetPendingCrossZoneDispatches)
            .await
            .expect("pending dispatches readable")
            .into_iter()
            .map(|record| record.message_key)
            .collect::<Vec<_>>();

        keys.sort_unstable();
        keys
    }

    /// A store that refuses every delivery write, standing in for any store
    /// failure between reading a peer block and the delivery being durable.
    fn store_refusing_deliveries() -> ActorRef<MockStorageActor> {
        let floor: Arc<Mutex<Option<Vec<u8>>>> = Arc::default();
        let tip: Arc<Mutex<Option<PeerChainTip>>> = Arc::default();
        let mut storage = MockStorageActor::new();

        storage
            .expect_handle_add_pending_cross_zone_dispatches()
            .returning(|_, _| {
                Err(storage::error::DbError::db_interaction_error(
                    "the store refused the write".to_owned(),
                )
                .into())
            });

        let written_floor = Arc::clone(&floor);
        storage
            .expect_handle_set_cross_zone_peer_floor_bytes()
            .returning(move |msg, _| {
                *written_floor.lock().expect("floor cell") = Some(msg.bytes);
                Ok(())
            });
        storage
            .expect_handle_get_cross_zone_peer_floor_bytes()
            .returning(move |_, _| Ok(floor.lock().expect("floor cell").clone()));

        let written_tip = Arc::clone(&tip);
        storage
            .expect_handle_set_cross_zone_peer_tip()
            .returning(move |msg, _| {
                *written_tip.lock().expect("tip cell") = Some(msg.tip);
                Ok(())
            });
        storage
            .expect_handle_get_cross_zone_peer_tip()
            .returning(move |_, _| Ok(*tip.lock().expect("tip cell")));

        MockStorageActor::spawn(storage)
    }

    /// Drives the state machine over a sequence of pass outcomes, with the read
    /// position after each, and returns the state it lands in.
    fn run_passes(passes: &[(PassOutcome, Option<u64>)]) -> WatcherState {
        let mut state = WatcherState::default();
        for (outcome, cursor) in passes {
            state.after_pass(*outcome, cursor.map(Slot::from));
        }
        state
    }

    #[test]
    fn passes_that_place_nothing_while_skipping_blocks_are_counted() {
        // A tip that stops tracking the peer is silent by construction: every
        // later block sits above it, is read past, and the floor moves over it,
        // so there is no stuck slot to count and nothing else to notice. The
        // count is not keyed by slot, because the peer keeps producing and each
        // such pass ends at a new one.
        let stranded = [
            (PassOutcome::Stranded, Some(4)),
            (PassOutcome::Stranded, Some(9)),
            (PassOutcome::Stranded, Some(14)),
        ];
        assert_eq!(run_passes(&stranded).stranded, 3);

        // Placing anything at all means the tip still tracks the peer.
        let mut recovered = stranded.to_vec();
        recovered.push((PassOutcome::Drained, Some(19)));
        assert_eq!(run_passes(&recovered).stranded, 0);

        // And an ordinary pass over a peer with nothing to say is not this.
        assert_eq!(run_passes(&[(PassOutcome::Drained, Some(4))]).stranded, 0);
    }

    #[test]
    fn every_way_of_ending_early_keeps_the_slot_coming_back() {
        // Undecodable and undelivered differ in whose problem they are, not in
        // what the watcher does about them: hold the floor and read the slot
        // again.
        for outcome in [
            PassOutcome::Undecodable(Slot::from(4)),
            PassOutcome::Undelivered(Slot::from(4)),
        ] {
            let mut state = WatcherState::default();
            assert_eq!(
                state.after_pass(outcome, Some(Slot::from(3))),
                Some((Slot::from(4), 1))
            );
        }
    }

    #[test]
    fn a_floor_without_a_tip_resumes_from_the_peers_genesis() {
        // A store written before chain pinning. The floor is cleared rather
        // than ignored so a crash mid-rebuild does not resume from it either.
        assert_eq!(
            resume_from(None, Some(checkpoint(7))),
            Resume {
                cursor: None,
                clear_floor: true
            }
        );
        assert_eq!(
            resume_from(Some(tip_at(2)), Some(checkpoint(7))),
            Resume {
                cursor: Some(checkpoint(7)),
                clear_floor: false
            },
            "an ordinary restart resumes where it left off and keeps its floor"
        );
        assert_eq!(
            resume_from(None, None),
            Resume {
                cursor: None,
                clear_floor: false
            },
            "a first start has no floor to clear"
        );
    }

    #[tokio::test]
    async fn watcher_persists_its_cursor_as_it_consumes() {
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 0), peer_block_msg(2, 1)]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(outcome, PassOutcome::Drained);
        assert!(checkpoint_eq_opt(cursor.as_ref(), Some(&checkpoint(1))));
        assert!(
            checkpoint_eq_opt(
                get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                    .await
                    .unwrap()
                    .as_ref(),
                Some(&checkpoint(1))
            ),
            "the cursor must be durable, not just in memory"
        );
        let mut expected = vec![message_key(&PEER_ZONE, 1, 0), message_key(&PEER_ZONE, 2, 0)];
        expected.sort_unstable();
        assert_eq!(recorded_keys(&storage_ref).await, expected);
    }

    #[tokio::test]
    async fn a_delivery_into_a_sequencer_only_program_is_never_recorded() {
        // Targets authorize their own sources, so the watcher no longer decides
        // who may reach what. It still refuses to queue a delivery the zone will
        // certainly refuse: the inbox is injected by this node alone, so a peer
        // naming it as a target is junk that would cost a pending slot and three
        // execution attempts.
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg_to(
                1,
                0,
                programs::cross_zone_inbox().id(),
            )]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(
            outcome,
            PassOutcome::Drained,
            "a message the watcher drops is not a failure"
        );
        assert!(
            recorded_keys(&storage_ref).await.is_empty(),
            "a message aimed at a sequencer-only program must not be recorded"
        );

        assert!(
            checkpoint_eq_opt(
                get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                    .await
                    .unwrap()
                    .as_ref(),
                Some(&checkpoint(0))
            ),
            "the slot was fully read, so the floor still advances"
        );
    }

    #[tokio::test]
    async fn a_delivery_to_an_unrelated_target_is_still_recorded() {
        // The watcher is not the authorization point any more. A target it knows
        // nothing about is recorded and delivered, and that target decides.
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg_to(
                1,
                0,
                programs::wrapped_token().id(),
            )]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(outcome, PassOutcome::Drained);
        assert_eq!(
            recorded_keys(&storage_ref).await.len(),
            1,
            "the watcher records it and lets the target refuse it"
        );
    }

    #[tokio::test]
    async fn watcher_records_every_delivery_it_reads() {
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;

        consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 0)]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        // The read cursor is durable, so once it advances this peer block is
        // never re-read. The record is the whole of what survives that: block
        // production drains it, and it outlives a restart. It is dropped when
        // the delivery itself becomes irreversible, not when it is included.
        let records = storage_ref
            .ask(GetPendingCrossZoneDispatches)
            .await
            .unwrap();
        assert_eq!(records.len(), 1, "the delivery must be recorded");
        assert_eq!(
            records[0].message_key,
            message_key(&PEER_ZONE, 1, 0),
            "the record is keyed by the message it delivers, so a replay is not double-tracked"
        );
        assert!(
            borsh::from_slice::<LeeTransaction>(&records[0].transaction).is_ok(),
            "the recorded bytes must decode, or the drain silently skips them"
        );
        assert_eq!(
            records[0].failed_attempts, 0,
            "a delivery that has never been attempted starts with a clean count"
        );
    }

    #[tokio::test]
    async fn a_recorded_delivery_names_the_hash_the_watcher_validated() {
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;

        consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 0)]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        let records = storage_ref
            .ask(GetPendingCrossZoneDispatches)
            .await
            .unwrap();
        assert_eq!(records.len(), 1, "the delivery must be recorded");
        let tx = borsh::from_slice::<LeeTransaction>(&records[0].transaction).unwrap();
        let LeeTransaction::Public(public_tx) = tx else {
            panic!("a dispatch is a public transaction");
        };
        let Ok(cross_zone_inbox_core::Instruction::Dispatch(msg)) =
            risc0_zkvm::serde::from_slice(&public_tx.message().instruction_data)
        else {
            panic!("the recorded transaction is an inbox dispatch");
        };

        // The indexer recomputes this independently when it re-derives the same
        // transaction; a different block here is what makes the two disagree.
        assert_eq!(
            msg.src_block_hash,
            chain_block(1).recompute_hash().0,
            "the delivery names the block the watcher read it from"
        );
    }

    #[tokio::test]
    async fn a_delivery_that_cannot_be_recorded_holds_the_floor() {
        let storage_ref = store_refusing_deliveries();
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 0)]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        // The floor is durable and nothing re-reads a slot below it, so a pass
        // that failed to record must not let it move, or the delivery is lost
        // rather than retried.
        assert_eq!(outcome, PassOutcome::Undelivered(Slot::from(0)));
        assert!(
            checkpoint_eq_opt(
                get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                    .await
                    .unwrap()
                    .as_ref(),
                None
            ),
            "the slot must stay re-readable"
        );
        // The tip is written after the deliveries, never before. Ahead of them a
        // crash in between makes the re-read see the block as already delivered
        // from, and its messages are never looked at again.
        assert_eq!(tip, None);
        assert_eq!(
            storage_ref
                .ask(GetCrossZonePeerTip {
                    peer_zone: PEER_ZONE
                })
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn watcher_resumes_from_the_persisted_cursor_without_rereading() {
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;

        consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 0), peer_block_msg(2, 1)]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;
        assert_eq!(recorded_keys(&storage_ref).await.len(), 2);

        // Restart: a fresh watcher seeds both its cursor and its chain tip from
        // the store. One that had to rebuild the tip in memory would accept
        // whatever block arrived first.
        let resumed = get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
            .await
            .unwrap();
        assert!(checkpoint_eq_opt(resumed.as_ref(), Some(&checkpoint(1))));
        let mut resumed_tip = storage_ref
            .ask(GetCrossZonePeerTip {
                peer_zone: PEER_ZONE,
            })
            .await
            .unwrap();
        assert_eq!(
            resumed_tip,
            Some(tip_at(2)),
            "the tip is durable, not just in memory"
        );

        // The sdk resumes the stream at cursor + 1, so only block 3 arrives.
        let mut resumed_cursor = resumed;
        consume_peer_stream(
            stream::iter(vec![peer_block_msg(3, 2)]),
            &peer_context(),
            &storage_ref,
            &mut resumed_cursor,
            &mut resumed_tip,
        )
        .await;

        let mut expected = vec![
            message_key(&PEER_ZONE, 1, 0),
            message_key(&PEER_ZONE, 2, 0),
            message_key(&PEER_ZONE, 3, 0),
        ];
        expected.sort_unstable();
        assert_eq!(
            recorded_keys(&storage_ref).await,
            expected,
            "only the unread block is recorded on the second pass"
        );
        assert!(checkpoint_eq_opt(
            get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                .await
                .unwrap()
                .as_ref(),
            Some(&checkpoint(2))
        ),);
    }

    #[tokio::test]
    async fn watcher_does_not_persist_past_an_undecodable_block() {
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![
                peer_block_msg(1, 0),
                undecodable_msg(1),
                peer_block_msg(3, 2),
            ]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        // A durable cursor makes this load-bearing: advancing past the bad block
        // would drop its messages permanently rather than until the next restart.
        assert_eq!(outcome, PassOutcome::Undecodable(Slot::from(1)));
        assert!(checkpoint_eq_opt(
            get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                .await
                .unwrap()
                .as_ref(),
            Some(&checkpoint(0))
        ),);
        assert_eq!(
            recorded_keys(&storage_ref).await,
            vec![message_key(&PEER_ZONE, 1, 0)],
            "the block after the failure is unread"
        );
    }

    #[tokio::test]
    async fn watcher_does_not_persist_inside_a_partially_failed_slot() {
        // One slot can carry several messages. Persisting after each message
        // would store a cursor the retry resumes past, so the message that
        // failed is never re-read and its delivery is lost for good.
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 4), undecodable_msg(4)]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(outcome, PassOutcome::Undecodable(Slot::from(4)));
        assert!(
            checkpoint_eq_opt(cursor.as_ref(), None),
            "slot 4 is re-read whole on the next pass"
        );
        assert!(checkpoint_eq_opt(
            get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                .await
                .unwrap()
                .as_ref(),
            None
        ));
        assert_eq!(
            recorded_keys(&storage_ref).await,
            vec![message_key(&PEER_ZONE, 1, 0)]
        );
    }

    #[tokio::test]
    async fn an_undecodable_block_stops_the_peer() {
        // This used to be read past after twenty attempts, which advanced the
        // floor over the hole and lost those messages rather than delaying
        // them: nothing after a hole can link. Stopping keeps the slot readable.
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;

        for _ in 0..3 {
            let outcome = consume_peer_stream(
                stream::iter(vec![
                    peer_block_msg(1, 0),
                    undecodable_msg(1),
                    peer_block_msg(3, 2),
                ]),
                &peer_context(),
                &storage_ref,
                &mut cursor,
                &mut tip,
            )
            .await;
            assert_eq!(outcome, PassOutcome::Undecodable(Slot::from(1)));
        }

        assert_eq!(
            recorded_keys(&storage_ref).await,
            vec![message_key(&PEER_ZONE, 1, 0)],
            "no pass reads past the slot it cannot decode"
        );
        assert!(
            checkpoint_eq_opt(
                get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                    .await
                    .unwrap()
                    .as_ref(),
                Some(&checkpoint(0))
            ),
            "the floor stays below it, so a fixed decoder recovers the messages"
        );
        assert_eq!(tip, Some(tip_at(1)));
    }

    #[tokio::test]
    async fn a_block_claiming_an_id_ahead_of_the_chain_is_not_delivered_from() {
        // The #677 suppression, end to end. The peer inscribes a block claiming
        // id 5 while its chain is at 1. Delivered, it would burn
        // message_key(PEER_ZONE, 5, 0), and the honest block 5 carrying a real
        // message at index 0 would then be no-oped by the inbox as a replay,
        // with the funds behind it already escrowed on the peer.
        //
        // The honest blocks behind it still deliver: stopping here would cost
        // the peer one inscription to end its own deliveries for good.
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;
        let pre_burn = produce_dummy_block(5, None, vec![emission()]);

        let outcome = consume_peer_stream(
            stream::iter(vec![
                peer_block_msg(1, 0),
                block_msg(&pre_burn, 1),
                peer_block_msg(2, 2),
                peer_block_msg(3, 3),
            ]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(outcome, PassOutcome::Drained);
        let mut expected = vec![
            message_key(&PEER_ZONE, 1, 0),
            message_key(&PEER_ZONE, 2, 0),
            message_key(&PEER_ZONE, 3, 0),
        ];
        expected.sort_unstable();
        assert_eq!(
            recorded_keys(&storage_ref).await,
            expected,
            "the key the peer aimed to burn is never recorded, and nothing else is held up"
        );
        assert_eq!(tip, Some(tip_at(3)));
    }

    #[tokio::test]
    async fn a_second_block_at_a_delivered_id_is_not_delivered_from() {
        // Both claim id 2, so on chain both deliveries key on (PEER_ZONE, 2, 0)
        // and the second is a replay the inbox no-ops.
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;
        let equivocation = produce_dummy_block(2, Some(HashType([9; 32])), vec![emission()]);

        let outcome = consume_peer_stream(
            stream::iter(vec![
                peer_block_msg(1, 0),
                peer_block_msg(2, 1),
                block_msg(&equivocation, 2),
            ]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(
            outcome,
            PassOutcome::Drained,
            "a peer equivocating about its own chain is not this node's failure"
        );
        let mut expected = vec![message_key(&PEER_ZONE, 1, 0), message_key(&PEER_ZONE, 2, 0)];
        expected.sort_unstable();
        assert_eq!(
            recorded_keys(&storage_ref).await,
            expected,
            "one delivery per id, whatever the peer publishes under it"
        );
        assert_eq!(tip, Some(tip_at(2)));
    }

    #[tokio::test]
    async fn a_block_that_does_not_link_to_the_tip_is_not_delivered_from() {
        // Not on the chain we verified, so nothing is delivered from it, and
        // the honest block at that id still is when it lands.
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;
        let forked = produce_dummy_block(2, Some(HashType([9; 32])), vec![emission()]);

        let outcome = consume_peer_stream(
            stream::iter(vec![
                peer_block_msg(1, 0),
                block_msg(&forked, 1),
                peer_block_msg(2, 2),
            ]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(outcome, PassOutcome::Drained);
        let mut expected = vec![message_key(&PEER_ZONE, 1, 0), message_key(&PEER_ZONE, 2, 0)];
        expected.sort_unstable();
        assert_eq!(
            recorded_keys(&storage_ref).await,
            expected,
            "the fork is passed over and the peer's own chain continues"
        );
        assert_eq!(tip, Some(tip_at(2)));
    }

    #[tokio::test]
    async fn a_watcher_with_no_tip_delivers_nothing_below_the_peers_genesis() {
        // A fresh watcher handed a mid-chain block has nothing to link it
        // against. Adopting it would let the peer choose where the chain starts
        // and burn every key below it with one block.
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg(2, 0)]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(
            outcome,
            PassOutcome::Stranded,
            "a pass that placed nothing while passing blocks over is how a peer goes quiet"
        );
        assert!(recorded_keys(&storage_ref).await.is_empty());
        assert_eq!(tip, None);
    }

    #[tokio::test]
    async fn a_tampered_header_hash_is_not_delivered_from() {
        // As correctly signed as any other block, since the signature does not
        // cover `header.hash`. Block 2 arriving behind it still delivers.
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;
        let mut tampered = chain_block(2);
        tampered.header.hash = HashType([9; 32]);

        let outcome = consume_peer_stream(
            stream::iter(vec![
                peer_block_msg(1, 0),
                block_msg(&tampered, 1),
                peer_block_msg(2, 2),
            ]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(outcome, PassOutcome::Drained);
        let mut expected = vec![message_key(&PEER_ZONE, 1, 0), message_key(&PEER_ZONE, 2, 0)];
        expected.sort_unstable();
        assert_eq!(recorded_keys(&storage_ref).await, expected);
        assert_eq!(tip, Some(tip_at(2)));
    }

    #[tokio::test]
    async fn rebuilding_a_missing_tip_clears_the_stale_floor_first() {
        // The tip is written per block and the floor per slot, so a crash
        // partway through the rebuild would otherwise leave a floor far above a
        // tip of 1, and nothing read after that restart could link.
        let (_dir, storage_ref) = store().await;
        set_cross_zone_peer_floor(&storage_ref, PEER_ZONE, checkpoint(5000))
            .await
            .unwrap();

        let floor = get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
            .await
            .unwrap();
        let tip = storage_ref
            .ask(GetCrossZonePeerTip {
                peer_zone: PEER_ZONE,
            })
            .await
            .unwrap();
        let resume = resume_from(tip, floor);
        assert!(
            checkpoint_eq_opt(resume.cursor.as_ref(), None),
            "the rebuild reads from genesis"
        );
        assert!(resume.clear_floor);

        clear_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
            .await
            .unwrap();
        assert!(
            get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                .await
                .unwrap()
                .is_none(),
            "and a crash mid-rebuild resumes from genesis too, not from slot 5000"
        );
    }
}
