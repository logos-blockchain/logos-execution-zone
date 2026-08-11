use std::{sync::Arc, time::Duration};

use common::{HashType, block::Block, transaction::LeeTransaction};
use cross_zone::{build_dispatch_from_emission, extract_emission};
use cross_zone_inbox_core::{CrossZoneRoute, message_key, routes_permit};
use futures::{Stream, StreamExt as _};
use lee::{GENESIS_BLOCK_ID, PublicKey};
use log::{debug, error, info, warn};
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use logos_blockchain_zone_sdk::{
    CommonHttpClient, Slot, ZoneMessage, adapter::NodeHttpClient, indexer::ZoneIndexer,
};
use storage::sequencer::{
    RocksDBIO,
    sequencer_cells::{PeerChainTip, PendingCrossZoneDispatchRecord},
};

use crate::{
    block_store::{
        clear_cross_zone_peer_floor, get_cross_zone_peer_floor, set_cross_zone_peer_floor,
    },
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

/// The per-peer settings one watcher pass needs.
struct PeerContext {
    peer_zone: [u8; 32],
    self_zone: [u8; 32],
    allowed_routes: Vec<CrossZoneRoute>,
    expected_pubkey: Option<PublicKey>,
}

/// Why one pass over a peer's stream ended.
///
/// All of them hold the delivery floor at the last slot the watcher consumed
/// whole, bar [`PassOutcome::Drained`] and [`PassOutcome::Stranded`], so the
/// next pass re-reads from there. Only a block that will not deserialize ends a
/// pass; [`link_against`] says why one that decodes never does.
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
    /// The slot it is stuck on and how many consecutive passes it has spent
    /// there. Keyed by slot so a failure at a new slot does not inherit an
    /// older slot's count.
    stalled: Option<(Slot, u32)>,
    /// Consecutive passes that placed nothing while skipping blocks. Not keyed
    /// by slot: the peer keeps producing, so every such pass ends at a new slot
    /// and a slot-keyed count would reset to one for ever.
    stranded: u32,
}

impl WatcherState {
    /// Folds one pass's outcome in, returning the slot the watcher is stuck on
    /// and how long it has been stuck, so the caller can say so.
    ///
    /// `cursor` is the read position after the pass, and is what tells a stream
    /// that truncated early apart from one that genuinely drained: the zone-sdk
    /// ends a stream on a fetch failure exactly as it does on catching up, so
    /// without it a flaky peer endpoint resets the count for ever and a watcher
    /// stuck for hours never says so.
    fn after_pass(&mut self, outcome: PassOutcome, cursor: Option<Slot>) -> Option<(Slot, u32)> {
        let slot = match outcome {
            PassOutcome::Drained | PassOutcome::Stranded => {
                if self.passed_the_stall(cursor) {
                    self.stalled = None;
                }
                self.stranded = match outcome {
                    PassOutcome::Stranded => self.stranded.saturating_add(1),
                    PassOutcome::Drained
                    | PassOutcome::Undecodable(_)
                    | PassOutcome::Undelivered(_) => 0,
                };
                return None;
            }
            PassOutcome::Undecodable(slot) | PassOutcome::Undelivered(slot) => slot,
        };

        let attempts = match self.stalled {
            Some((stuck_on, attempts)) if stuck_on == slot => attempts.saturating_add(1),
            _ => 1,
        };
        self.stalled = Some((slot, attempts));
        self.stalled
    }

    /// Whether the read position is now past whatever the watcher was stuck on.
    /// Vacuously true when it was not stuck.
    fn passed_the_stall(self, cursor: Option<Slot>) -> bool {
        self.stalled
            .is_none_or(|(stuck_on, _)| cursor.is_some_and(|read_to| read_to >= stuck_on))
    }
}

/// What a starting watcher does with its stored floor and chain tip.
#[derive(Debug, PartialEq, Eq)]
struct Resume {
    /// Where to read from. `None` is the peer's genesis.
    cursor: Option<Slot>,
    /// Whether the stored floor has to be dropped before anything is read.
    clear_floor: bool,
}

/// Where a peer block sits relative to the chain this watcher has delivered
/// from.
#[derive(Debug, PartialEq, Eq)]
enum Link {
    /// The next block on the peer's chain, carrying its recomputed hash.
    Next(HashType),
    /// At or below the tip, so already delivered from. The ordinary shape of a
    /// re-read slot, and how an equivocating second block at one id is refused.
    AlreadySeen,
    /// Not on the chain this watcher is following, so not deliverable. Read on:
    /// the peer's own next block still links to the tip, and treating this as
    /// terminal would hand the peer a way to stop its deliveries permanently.
    OffChain(String),
}

/// Whether `block` continues the peer chain pinned by `tip`.
///
/// This is what closes the suppression. A delivered message's replay key covers
/// `(src_zone, src_block_id, src_tx_index)` and nothing else, so a peer that can
/// get a block delivered under an id of its choosing burns the key an honest
/// block would later use, and the inbox then no-ops the real message as a
/// replay. Off a hash link ids are only claimable in order, so the only id
/// within reach is the one the peer is about to publish anyway.
///
/// Nothing but [`Link::Next`] is ever delivered from, and nothing but a block
/// that will not decode stops the pass. A peer can inscribe anything it likes on
/// its own channel, so a block this watcher cannot place is read past rather
/// than treated as the end of the chain: the peer's own next honest block still
/// links to the tip.
fn link_against(
    tip: Option<PeerChainTip>,
    block: &Block,
    expected_pubkey: Option<&PublicKey>,
) -> Link {
    // The channel authorizes who may write, not what they may claim, so the
    // pinned key is what says this node's own sequencer produced the block. The
    // header's own `producer` is checked against it as well: the signature is
    // what proves authorship, the comparison keeps the pinned key in charge of
    // which producer is acceptable here.
    if expected_pubkey.is_some_and(|key| &block.header.producer != key || !block.is_signed_by(key))
    {
        return Link::OffChain("block-signing key does not match the pinned key".to_owned());
    }

    let recomputed = block.recompute_hash();
    if recomputed != block.header.hash {
        // The signature does not cover this field, so a correctly signed block
        // may still carry a bogus one, and the peer's own next block links
        // against the recomputed value rather than this one.
        return Link::OffChain(format!(
            "block {} carries header hash {} but its contents hash to {recomputed}",
            block.header.block_id, block.header.hash
        ));
    }

    let Some(tip) = tip else {
        return if block.header.block_id == GENESIS_BLOCK_ID {
            Link::Next(recomputed)
        } else {
            Link::OffChain(format!(
                "block {} is the first one read, but a watcher with no stored chain tip has to start at the peer's genesis block {GENESIS_BLOCK_ID}",
                block.header.block_id
            ))
        };
    };

    if block.header.block_id <= tip.block_id {
        return Link::AlreadySeen;
    }
    if block.header.block_id > tip.block_id.saturating_add(1) {
        return Link::OffChain(format!(
            "block {} skips past {}, which is either a hole in what this node read or an id claimed ahead of the peer's chain",
            block.header.block_id,
            tip.block_id.saturating_add(1)
        ));
    }
    if block.header.prev_block_hash != tip.block_hash {
        return Link::OffChain(format!(
            "block {} does not follow block {} we delivered from: it links to {} rather than {}",
            block.header.block_id, tip.block_id, block.header.prev_block_hash, tip.block_hash
        ));
    }
    Link::Next(recomputed)
}

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
const fn resume_from(tip: Option<PeerChainTip>, floor: Option<Slot>) -> Resume {
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
/// proves they have stopped. Each watcher holds an `Arc<RocksDBIO>`, so a
/// watcher still running keeps the `RocksDB` lock held and a restarting
/// sequencer cannot reopen its home directory.
#[must_use]
pub fn spawn_watchers(
    bedrock_config: &BedrockConfig,
    cross_zone: &CrossZoneConfig,
    poll_interval: Duration,
    dbio: &Arc<RocksDBIO>,
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
            ZoneIndexer::new(ChannelId::from(peer.channel_id), node),
            PeerContext {
                peer_zone: peer.channel_id,
                self_zone,
                allowed_routes: peer.allowed_routes,
                expected_pubkey,
            },
            poll_interval,
            Arc::clone(dbio),
        )));
    }

    TaskGroup::new(tasks)
}

#[expect(
    clippy::infinite_loop,
    reason = "the peer watcher runs for the lifetime of the sequencer process"
)]
async fn watch_peer(
    zone_indexer: ZoneIndexer<NodeHttpClient>,
    peer: PeerContext,
    poll_interval: Duration,
    dbio: Arc<RocksDBIO>,
) {
    let peer_zone = peer.peer_zone;
    info!(
        "Cross-zone watcher started for peer {}",
        hex::encode(peer_zone)
    );

    // Resume from the delivery floor: the highest slot every message of which
    // was decoded and recorded. Re-reading a peer channel is safe (the dispatch
    // key is content-addressed and the inbox no-ops a replay) but re-records
    // every already-delivered message, so without this a restart replayed the
    // peer's whole history into the store.
    let floor = match get_cross_zone_peer_floor(&dbio, peer_zone) {
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
    let mut tip = match dbio.get_cross_zone_peer_tip(peer_zone) {
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
        if let Err(err) = clear_cross_zone_peer_floor(&dbio, peer_zone) {
            error!(
                "Watcher could not clear the stale delivery floor for peer {}: {err:#}. Stopping this watcher rather than rebuilding its chain against a floor a restart would resume from.",
                hex::encode(peer_zone)
            );
            return;
        }
    }
    let mut cursor = resume.cursor;
    if let Some(slot) = cursor {
        info!(
            "Resuming watcher for peer {} from slot {slot:?}",
            hex::encode(peer_zone)
        );
    }

    // In memory, and rebuilt from the store on every start: it says only how
    // loud to be about a slot this watcher is stuck on.
    let mut state = WatcherState::default();
    loop {
        let stream = match zone_indexer.next_messages(cursor).await {
            Ok(stream) => stream,
            Err(err) => {
                error!(
                    "Watcher next_messages failed for peer {}: {err}",
                    hex::encode(peer_zone)
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };
        let outcome = consume_peer_stream(stream, &peer, &dbio, &mut cursor, &mut tip).await;

        if let Some((slot, attempts)) = state.after_pass(outcome, cursor)
            && alerts_at(attempts)
        {
            error!(
                "Watcher for peer {} has been stuck at slot {slot:?} for {attempts} passes. Nothing from that peer is being delivered until it clears, and the delivery floor stays at {:?} so the slot keeps coming back.",
                hex::encode(peer_zone),
                get_cross_zone_peer_floor(&dbio, peer_zone).ok().flatten()
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
async fn consume_peer_stream<S>(
    stream: S,
    peer: &PeerContext,
    dbio: &RocksDBIO,
    cursor: &mut Option<Slot>,
    tip: &mut Option<PeerChainTip>,
) -> PassOutcome
where
    S: Stream<Item = (ZoneMessage, Slot)>,
{
    let mut stream = std::pin::pin!(stream);
    // The slot being consumed: every message of it seen so far is handled, but
    // there may be more to come, so the cursor may not advance onto it yet.
    let mut in_progress: Option<Slot> = None;
    // What the pass did with the blocks it read, so a peer going quiet behind a
    // tip that no longer tracks it is distinguishable from one with nothing to
    // say.
    let mut placed = 0_usize;
    let mut skipped = 0_usize;

    while let Some((msg, slot)) = stream.next().await {
        if in_progress != Some(slot) {
            // A message from a later slot means the previous one completed.
            if let Some(done) = in_progress {
                advance_cursor(dbio, peer.peer_zone, cursor, done);
            }
            in_progress = Some(slot);
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
                match link_against(*tip, &block, peer.expected_pubkey.as_ref()) {
                    Link::AlreadySeen => {
                        debug!(
                            "Watcher ignoring peer {} block {}: at or below the block it has already delivered from",
                            hex::encode(peer.peer_zone),
                            block.header.block_id
                        );
                    }
                    Link::OffChain(reason) => {
                        skipped = skipped.saturating_add(1);
                        warn!(
                            "Watcher not delivering from peer {} block at slot {slot:?}: {reason}. Reading on; the peer's next block that continues the chain still delivers.",
                            hex::encode(peer.peer_zone)
                        );
                    }
                    Link::Next(block_hash) => {
                        if !record_block_deliveries(&block, peer, dbio) {
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
                        if let Err(err) = dbio.put_cross_zone_peer_tip(peer.peer_zone, next) {
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
        advance_cursor(dbio, peer.peer_zone, cursor, done);
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
fn advance_cursor(dbio: &RocksDBIO, peer_zone: [u8; 32], cursor: &mut Option<Slot>, slot: Slot) {
    *cursor = Some(slot);
    if let Err(err) = set_cross_zone_peer_floor(dbio, peer_zone, slot) {
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
fn record_block_deliveries(block: &Block, peer: &PeerContext, dbio: &RocksDBIO) -> bool {
    let peer_zone = peer.peer_zone;
    let self_zone = peer.self_zone;
    let allowed_routes = peer.allowed_routes.as_slice();
    // Collected and written once. The pending list is a single value, so a write
    // per delivery would rewrite the whole list once per message, which is
    // quadratic in a peer block that carries many of them, on a task holding the
    // lock block production needs.
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
        // Mirrors the inbox guest, which is the authority. Dropping here keeps
        // an unroutable message from becoming a record that production would
        // feed in and give up on three blocks later.
        if !routes_permit(
            allowed_routes,
            message.program_id,
            emission.target_program_id,
        ) {
            warn!(
                "Watcher dropping message from peer {}: no route from that source program to that target",
                hex::encode(peer_zone)
            );
            continue;
        }

        let src_tx_index = u32::try_from(index).unwrap_or(u32::MAX);
        let dispatch = build_dispatch_from_emission(
            peer_zone,
            block.header.block_id,
            src_tx_index,
            message.program_id,
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
    match dbio.add_pending_cross_zone_dispatches(deliveries) {
        // Fewer accepted than offered means the rest were recorded by an earlier
        // pass over the same slot, which the retry loop repeats for as long as
        // the slot stays stuck.
        Ok(accepted) => {
            if accepted > 0 {
                info!(
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
    use common::test_utils::produce_dummy_block;
    use futures::stream;
    use lee::{
        PublicTransaction,
        public_transaction::{Message, WitnessSet},
    };
    use logos_blockchain_core::mantle::ops::channel::{MsgId, inscribe::Inscription};
    use logos_blockchain_zone_sdk::ZoneBlock;
    use ping_core::{SenderInstruction, ping_record_pda};
    use storage::sequencer::{DB_META_PENDING_CROSS_ZONE_DISPATCHES_KEY, RocksDBIO};
    use tempfile::TempDir;

    use super::*;

    const SELF_ZONE: [u8; 32] = [1; 32];
    const PEER_ZONE: [u8; 32] = [2; 32];

    fn peer_context() -> PeerContext {
        PeerContext {
            peer_zone: PEER_ZONE,
            self_zone: SELF_ZONE,
            allowed_routes: vec![CrossZoneRoute {
                src_program_id: programs::ping_sender().id(),
                target_program_id: programs::ping_receiver().id(),
            }],
            expected_pubkey: None,
        }
    }

    /// A store backed by a temp dir. The dir is returned so it outlives the db.
    fn store() -> (TempDir, RocksDBIO) {
        let dir = tempfile::tempdir().expect("temp dir");
        let genesis = produce_dummy_block(0, None, vec![]);
        let dbio = RocksDBIO::create(dir.path(), &genesis, &lee::V03State::new()).expect("db");
        (dir, dbio)
    }

    /// A `ping_sender` emission addressed to `SELF_ZONE`.
    fn emission() -> LeeTransaction {
        emission_to(programs::ping_receiver().id())
    }

    /// A `ping_sender` emission aimed at `target_program_id`. The sender lets its
    /// caller name any target, which is exactly why the route has to pin the
    /// pair rather than the target alone.
    fn emission_to(target_program_id: lee_core::program::ProgramId) -> LeeTransaction {
        let receiver_id = programs::ping_receiver().id();
        let send = SenderInstruction::Send {
            outbox_program_id: programs::cross_zone_outbox().id(),
            target_zone: SELF_ZONE,
            target_program_id,
            target_accounts: vec![ping_record_pda(receiver_id).into_value()],
            payload: b"hi".to_vec(),
            ordinal: 0,
        };
        let message = Message::new_feeless(programs::ping_sender().id(), vec![], vec![], send);
        LeeTransaction::Public(PublicTransaction::new(
            message,
            WitnessSet::from_raw_parts(vec![]),
        ))
    }

    fn peer_msg(data: Vec<u8>, slot: u64) -> (ZoneMessage, Slot) {
        (
            ZoneMessage::Block(ZoneBlock {
                id: MsgId::from([0; 32]),
                data: Inscription::try_from(data).expect("test inscription is within bounds"),
            }),
            Slot::from(slot),
        )
    }

    /// The peer's chain from its genesis up to and including `block_id`, each
    /// block linked to the one before it and carrying one emission for this
    /// zone. Empty below [`GENESIS_BLOCK_ID`].
    fn chain_to(block_id: u64) -> Vec<Block> {
        let mut blocks: Vec<Block> = Vec::new();
        for id in GENESIS_BLOCK_ID..=block_id {
            let prev = blocks.last().map(|block| block.header.hash);
            blocks.push(produce_dummy_block(id, prev, vec![emission()]));
        }
        blocks
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

    fn block_msg(block: &Block, slot: u64) -> (ZoneMessage, Slot) {
        peer_msg(borsh::to_vec(block).expect("block serializes"), slot)
    }

    /// A stream item carrying the peer's block `block_id`.
    fn peer_block_msg(block_id: u64, slot: u64) -> (ZoneMessage, Slot) {
        block_msg(&chain_block(block_id), slot)
    }

    /// A stream item carrying a block whose one emission targets
    /// `target_program_id`.
    fn peer_block_msg_to(
        block_id: u64,
        slot: u64,
        target_program_id: lee_core::program::ProgramId,
    ) -> (ZoneMessage, Slot) {
        block_msg(&chain_block_to(block_id, target_program_id), slot)
    }

    /// The tip a watcher holds after delivering up to `block_id`.
    fn tip_at(block_id: u64) -> PeerChainTip {
        PeerChainTip {
            block_id,
            block_hash: chain_hash(block_id),
        }
    }

    fn undecodable_msg(slot: u64) -> (ZoneMessage, Slot) {
        peer_msg(b"not a block".to_vec(), slot)
    }

    /// The message keys recorded so far, in insertion order.
    fn recorded_keys(dbio: &RocksDBIO) -> Vec<[u8; 32]> {
        dbio.get_pending_cross_zone_dispatches()
            .expect("pending dispatches readable")
            .into_iter()
            .map(|record| record.message_key)
            .collect()
    }

    /// Makes every later pending-dispatch read fail, standing in for any store
    /// failure between reading a peer block and the delivery being durable.
    /// Recording reads the list before it writes it, so a value that will not
    /// decode is enough.
    fn break_the_dispatch_store(dbio: &RocksDBIO) {
        let cf = dbio
            .db
            .cf_handle(storage::CF_META_NAME)
            .expect("meta column family");
        let key = borsh::to_vec(&DB_META_PENDING_CROSS_ZONE_DISPATCHES_KEY).expect("key encodes");
        dbio.db
            .put_cf(&cf, key, b"not a pending dispatch list")
            .expect("write");
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

    fn stall(slot: u64, cursor: Option<u64>) -> (PassOutcome, Option<u64>) {
        (PassOutcome::Undecodable(Slot::from(slot)), cursor)
    }

    #[test]
    fn a_stuck_slot_is_counted_but_never_read_past() {
        // The watcher used to give up on a slot and read past it. Counting is
        // now only how loud to be about one it is stuck on.
        let passes = vec![stall(4, Some(3)); 3];
        assert_eq!(run_passes(&passes).stalled, Some((Slot::from(4), 3)));

        let long = vec![
            stall(4, Some(3));
            usize::try_from(STUCK_SLOT_ALERT_PASSES).expect("alert threshold fits") * 2
        ];
        assert_eq!(
            run_passes(&long).stalled,
            Some((Slot::from(4), STUCK_SLOT_ALERT_PASSES.saturating_mul(2))),
            "a slot is retried for as long as it stays stuck"
        );
    }

    #[test]
    fn a_stream_that_ended_before_the_stalled_slot_does_not_reset_the_count() {
        // The zone-sdk ends a stream on a fetch failure exactly as it does on
        // catching up. Treating that as a clean pass would reset the count for
        // ever, and a watcher stuck for hours would never say so.
        let mut passes = vec![stall(4, Some(3)); 5];
        passes.push((PassOutcome::Drained, Some(3)));
        let state = run_passes(&passes);
        assert_eq!(
            state.stalled,
            Some((Slot::from(4), 5)),
            "the count survives a pass that never reached the stalled slot"
        );

        // Getting past it is what actually clears the stall.
        let mut read_past = vec![stall(4, Some(3)); 5];
        read_past.push((PassOutcome::Drained, Some(7)));
        assert_eq!(run_passes(&read_past).stalled, None);
    }

    #[test]
    fn a_stall_says_so_on_a_cadence_rather_than_once() {
        // Reporting only on the crossing leaves a watcher that never recovers
        // looking resolved, which is the failure this whole commit is about.
        assert!(!alerts_at(0));
        assert!(!alerts_at(1));
        assert!(!alerts_at(STUCK_SLOT_ALERT_PASSES - 1));
        assert!(alerts_at(STUCK_SLOT_ALERT_PASSES));
        assert!(!alerts_at(STUCK_SLOT_ALERT_PASSES + 1));
        assert!(alerts_at(STUCK_SLOT_ALERT_PASSES * 3));
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
    fn a_stall_at_a_new_slot_starts_its_own_count() {
        let passes = vec![stall(4, Some(3)), stall(4, Some(3)), stall(9, Some(8))];
        assert_eq!(run_passes(&passes).stalled, Some((Slot::from(9), 1)));
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
            assert_eq!(
                run_passes(&[(outcome, Some(3))]).stalled,
                Some((Slot::from(4), 1))
            );
        }
    }

    #[test]
    fn only_the_next_block_off_the_tip_links() {
        let tip = Some(tip_at(2));

        assert_eq!(
            link_against(tip, &chain_block(3), None),
            Link::Next(chain_hash(3)),
            "the block that continues the chain is the one delivered from"
        );

        // The #677 suppression. The peer's chain is public, so the version that
        // matters is the block linking correctly and lying only about the id:
        // one with no link at all is caught by the check below and proves
        // nothing about this one.
        assert!(matches!(
            link_against(
                tip,
                &produce_dummy_block(5, Some(chain_hash(2)), vec![emission()]),
                None
            ),
            Link::OffChain(_)
        ));
        assert!(matches!(
            link_against(tip, &produce_dummy_block(5, None, vec![emission()]), None),
            Link::OffChain(_)
        ));

        // Two blocks claiming one id collapse to one key on chain, so
        // delivering from both delivers one message twice.
        assert_eq!(link_against(tip, &chain_block(2), None), Link::AlreadySeen);
        assert_eq!(
            link_against(
                tip,
                &produce_dummy_block(2, Some(HashType([9; 32])), vec![emission()]),
                None
            ),
            Link::AlreadySeen
        );

        // Right id, wrong ancestry: the peer forked at our tip, or reset it.
        assert!(matches!(
            link_against(
                tip,
                &produce_dummy_block(3, Some(HashType([9; 32])), vec![emission()]),
                None
            ),
            Link::OffChain(_)
        ));
    }

    #[test]
    fn a_watcher_with_no_tip_starts_at_the_peers_genesis() {
        assert_eq!(
            link_against(None, &chain_block(GENESIS_BLOCK_ID), None),
            Link::Next(chain_hash(GENESIS_BLOCK_ID))
        );
        // Anchoring on whatever arrived first is the whole attack: the peer
        // would pick the id, and every key below it with one block.
        assert!(matches!(
            link_against(None, &chain_block(GENESIS_BLOCK_ID + 1), None),
            Link::OffChain(_)
        ));
    }

    #[test]
    fn a_block_whose_header_hash_is_not_its_contents_is_off_chain() {
        // A correctly signed block can still carry any value in `header.hash`.
        let mut tampered = chain_block(3);
        tampered.header.hash = HashType([9; 32]);
        assert!(matches!(
            link_against(Some(tip_at(2)), &tampered, None),
            Link::OffChain(_)
        ));
    }

    #[test]
    fn a_block_not_signed_by_the_pinned_key_is_not_delivered_from() {
        let signer = lee::PublicKey::new_from_private_key(
            &lee::PrivateKey::try_new([37; 32]).expect("test key"),
        );
        assert_eq!(
            link_against(None, &chain_block(GENESIS_BLOCK_ID), Some(&signer)),
            Link::Next(chain_hash(GENESIS_BLOCK_ID)),
            "produce_dummy_block signs with this key, so the pin must accept it"
        );

        let other = lee::PublicKey::try_new([42; 32]).expect("test key");
        assert!(matches!(
            link_against(None, &chain_block(GENESIS_BLOCK_ID), Some(&other)),
            Link::OffChain(_)
        ));
    }

    #[test]
    fn a_floor_without_a_tip_resumes_from_the_peers_genesis() {
        // A store written before chain pinning. The floor is cleared rather
        // than ignored so a crash mid-rebuild does not resume from it either.
        assert_eq!(
            resume_from(None, Some(Slot::from(7))),
            Resume {
                cursor: None,
                clear_floor: true
            }
        );
        assert_eq!(
            resume_from(Some(tip_at(2)), Some(Slot::from(7))),
            Resume {
                cursor: Some(Slot::from(7)),
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
        let (_dir, dbio) = store();
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 0), peer_block_msg(2, 1)]),
            &peer_context(),
            &dbio,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(outcome, PassOutcome::Drained);
        assert_eq!(cursor, Some(Slot::from(1)));
        assert_eq!(
            get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap(),
            Some(Slot::from(1)),
            "the cursor must be durable, not just in memory"
        );
        assert_eq!(
            recorded_keys(&dbio),
            vec![message_key(&PEER_ZONE, 1, 0), message_key(&PEER_ZONE, 2, 0)]
        );
    }

    #[tokio::test]
    async fn a_delivery_with_no_route_is_never_recorded() {
        // The peer is routed to ping_receiver only. A bridging zone would also
        // route its lock program to wrapped_token, and `ping_sender` lets its
        // caller name wrapped_token as the target, so without the pair check
        // this emission would be recorded and delivered, minting with nothing
        // locked behind it. The guest rejects it too; dropping here keeps it
        // from becoming a record production feeds in and gives up on.
        let (_dir, dbio) = store();
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg_to(
                1,
                0,
                programs::wrapped_token().id(),
            )]),
            &peer_context(),
            &dbio,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(
            outcome,
            PassOutcome::Drained,
            "an unroutable message is not a failure"
        );
        assert!(
            recorded_keys(&dbio).is_empty(),
            "a message with no route must not be recorded"
        );
        assert_eq!(
            get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap(),
            Some(Slot::from(0)),
            "the slot was fully read, so the floor still advances"
        );
    }

    #[tokio::test]
    async fn watcher_records_every_delivery_it_reads() {
        let (_dir, dbio) = store();
        let mut cursor = None;
        let mut tip = None;

        consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 0)]),
            &peer_context(),
            &dbio,
            &mut cursor,
            &mut tip,
        )
        .await;

        // The read cursor is durable, so once it advances this peer block is
        // never re-read. The record is the whole of what survives that: block
        // production drains it, and it outlives a restart. It is dropped when
        // the delivery itself becomes irreversible, not when it is included.
        let records = dbio.get_pending_cross_zone_dispatches().unwrap();
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
    async fn a_delivery_that_cannot_be_recorded_holds_the_floor() {
        let (_dir, dbio) = store();
        break_the_dispatch_store(&dbio);
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 0)]),
            &peer_context(),
            &dbio,
            &mut cursor,
            &mut tip,
        )
        .await;

        // The floor is durable and nothing re-reads a slot below it, so a pass
        // that failed to record must not let it move, or the delivery is lost
        // rather than retried.
        assert_eq!(outcome, PassOutcome::Undelivered(Slot::from(0)));
        assert_eq!(
            get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap(),
            None,
            "the slot must stay re-readable"
        );
        // The tip is written after the deliveries, never before. Ahead of them a
        // crash in between makes the re-read see the block as already delivered
        // from, and its messages are never looked at again.
        assert_eq!(tip, None);
        assert_eq!(dbio.get_cross_zone_peer_tip(PEER_ZONE).unwrap(), None);
    }

    #[tokio::test]
    async fn watcher_resumes_from_the_persisted_cursor_without_rereading() {
        let (_dir, dbio) = store();
        let mut cursor = None;
        let mut tip = None;

        consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 0), peer_block_msg(2, 1)]),
            &peer_context(),
            &dbio,
            &mut cursor,
            &mut tip,
        )
        .await;
        assert_eq!(recorded_keys(&dbio).len(), 2);

        // Restart: a fresh watcher seeds both its cursor and its chain tip from
        // the store. One that had to rebuild the tip in memory would accept
        // whatever block arrived first.
        let resumed = get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap();
        assert_eq!(resumed, Some(Slot::from(1)));
        let mut resumed_tip = dbio.get_cross_zone_peer_tip(PEER_ZONE).unwrap();
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
            &dbio,
            &mut resumed_cursor,
            &mut resumed_tip,
        )
        .await;

        assert_eq!(
            recorded_keys(&dbio),
            vec![
                message_key(&PEER_ZONE, 1, 0),
                message_key(&PEER_ZONE, 2, 0),
                message_key(&PEER_ZONE, 3, 0)
            ],
            "only the unread block is recorded on the second pass"
        );
        assert_eq!(
            get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap(),
            Some(Slot::from(2))
        );
    }

    #[tokio::test]
    async fn watcher_does_not_persist_past_an_undecodable_block() {
        let (_dir, dbio) = store();
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![
                peer_block_msg(1, 0),
                undecodable_msg(1),
                peer_block_msg(3, 2),
            ]),
            &peer_context(),
            &dbio,
            &mut cursor,
            &mut tip,
        )
        .await;

        // A durable cursor makes this load-bearing: advancing past the bad block
        // would drop its messages permanently rather than until the next restart.
        assert_eq!(outcome, PassOutcome::Undecodable(Slot::from(1)));
        assert_eq!(
            get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap(),
            Some(Slot::from(0))
        );
        assert_eq!(
            recorded_keys(&dbio),
            vec![message_key(&PEER_ZONE, 1, 0)],
            "the block after the failure is unread"
        );
    }

    #[tokio::test]
    async fn watcher_does_not_persist_inside_a_partially_failed_slot() {
        // One slot can carry several messages. Persisting after each message
        // would store a cursor the retry resumes past, so the message that
        // failed is never re-read and its delivery is lost for good.
        let (_dir, dbio) = store();
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 4), undecodable_msg(4)]),
            &peer_context(),
            &dbio,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(outcome, PassOutcome::Undecodable(Slot::from(4)));
        assert_eq!(cursor, None, "slot 4 is re-read whole on the next pass");
        assert_eq!(get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap(), None);
        assert_eq!(recorded_keys(&dbio), vec![message_key(&PEER_ZONE, 1, 0)]);
    }

    #[tokio::test]
    async fn an_undecodable_block_stops_the_peer() {
        // This used to be read past after twenty attempts, which advanced the
        // floor over the hole and lost those messages rather than delaying
        // them: nothing after a hole can link. Stopping keeps the slot readable.
        let (_dir, dbio) = store();
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
                &dbio,
                &mut cursor,
                &mut tip,
            )
            .await;
            assert_eq!(outcome, PassOutcome::Undecodable(Slot::from(1)));
        }

        assert_eq!(
            recorded_keys(&dbio),
            vec![message_key(&PEER_ZONE, 1, 0)],
            "no pass reads past the slot it cannot decode"
        );
        assert_eq!(
            get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap(),
            Some(Slot::from(0)),
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
        let (_dir, dbio) = store();
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
            &dbio,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(outcome, PassOutcome::Drained);
        assert_eq!(
            recorded_keys(&dbio),
            vec![
                message_key(&PEER_ZONE, 1, 0),
                message_key(&PEER_ZONE, 2, 0),
                message_key(&PEER_ZONE, 3, 0)
            ],
            "the key the peer aimed to burn is never recorded, and nothing else is held up"
        );
        assert_eq!(tip, Some(tip_at(3)));
    }

    #[tokio::test]
    async fn a_second_block_at_a_delivered_id_is_not_delivered_from() {
        // Both claim id 2, so on chain both deliveries key on (PEER_ZONE, 2, 0)
        // and the second is a replay the inbox no-ops.
        let (_dir, dbio) = store();
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
            &dbio,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(
            outcome,
            PassOutcome::Drained,
            "a peer equivocating about its own chain is not this node's failure"
        );
        assert_eq!(
            recorded_keys(&dbio),
            vec![message_key(&PEER_ZONE, 1, 0), message_key(&PEER_ZONE, 2, 0)],
            "one delivery per id, whatever the peer publishes under it"
        );
        assert_eq!(tip, Some(tip_at(2)));
    }

    #[tokio::test]
    async fn a_block_that_does_not_link_to_the_tip_is_not_delivered_from() {
        // Not on the chain we verified, so nothing is delivered from it, and
        // the honest block at that id still is when it lands.
        let (_dir, dbio) = store();
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
            &dbio,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(outcome, PassOutcome::Drained);
        assert_eq!(
            recorded_keys(&dbio),
            vec![message_key(&PEER_ZONE, 1, 0), message_key(&PEER_ZONE, 2, 0)],
            "the fork is passed over and the peer's own chain continues"
        );
        assert_eq!(tip, Some(tip_at(2)));
    }

    #[tokio::test]
    async fn a_watcher_with_no_tip_delivers_nothing_below_the_peers_genesis() {
        // A fresh watcher handed a mid-chain block has nothing to link it
        // against. Adopting it would let the peer choose where the chain starts
        // and burn every key below it with one block.
        let (_dir, dbio) = store();
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg(2, 0)]),
            &peer_context(),
            &dbio,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(
            outcome,
            PassOutcome::Stranded,
            "a pass that placed nothing while passing blocks over is how a peer goes quiet"
        );
        assert!(recorded_keys(&dbio).is_empty());
        assert_eq!(tip, None);
    }

    #[tokio::test]
    async fn a_tampered_header_hash_is_not_delivered_from() {
        // As correctly signed as any other block, since the signature does not
        // cover `header.hash`. Block 2 arriving behind it still delivers.
        let (_dir, dbio) = store();
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
            &dbio,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(outcome, PassOutcome::Drained);
        assert_eq!(
            recorded_keys(&dbio),
            vec![message_key(&PEER_ZONE, 1, 0), message_key(&PEER_ZONE, 2, 0)]
        );
        assert_eq!(tip, Some(tip_at(2)));
    }

    #[tokio::test]
    async fn rebuilding_a_missing_tip_clears_the_stale_floor_first() {
        // The tip is written per block and the floor per slot, so a crash
        // partway through the rebuild would otherwise leave a floor far above a
        // tip of 1, and nothing read after that restart could link.
        let (_dir, dbio) = store();
        set_cross_zone_peer_floor(&dbio, PEER_ZONE, Slot::from(5000)).unwrap();

        let floor = get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap();
        let tip = dbio.get_cross_zone_peer_tip(PEER_ZONE).unwrap();
        let resume = resume_from(tip, floor);
        assert_eq!(resume.cursor, None, "the rebuild reads from genesis");
        assert!(resume.clear_floor);

        clear_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap();
        assert_eq!(
            get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap(),
            None,
            "and a crash mid-rebuild resumes from genesis too, not from slot 5000"
        );
    }
}
