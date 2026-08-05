use std::{sync::Arc, time::Duration};

use common::{block::Block, transaction::LeeTransaction};
use cross_zone::{build_dispatch_from_emission, extract_emission};
use cross_zone_inbox_core::{CrossZoneRoute, message_key, routes_permit};
use futures::{Stream, StreamExt as _};
use lee::PublicKey;
use log::{debug, error, info, warn};
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use logos_blockchain_zone_sdk::{
    CommonHttpClient, Slot, ZoneMessage, adapter::NodeHttpClient, indexer::ZoneIndexer,
};
use storage::sequencer::{RocksDBIO, sequencer_cells::PendingCrossZoneDispatchRecord};

use crate::{
    block_store::{get_cross_zone_peer_floor, set_cross_zone_peer_floor},
    config::{BedrockConfig, CrossZoneConfig},
    task_group::TaskGroup,
};

/// Consecutive passes a watcher re-reads the same undecodable slot before giving
/// up and reading past it.
///
/// One pass per poll interval, which is the block time, so this is minutes of
/// retrying rather than seconds. A transient failure (a truncated read, a peer
/// mid-upgrade) heals well inside that; a block this node genuinely cannot
/// decode does not heal at all, and waiting longer only delays every later
/// message behind it.
const DECODE_RETRY_LIMIT: u32 = 20;

/// The per-peer settings one watcher pass needs.
struct PeerContext {
    peer_zone: [u8; 32],
    self_zone: [u8; 32],
    allowed_routes: Vec<CrossZoneRoute>,
    expected_pubkey: Option<PublicKey>,
}

/// What a pass may do about a slot the watcher cannot decode, and whether it may
/// still move the durable delivery floor.
///
/// The two are one decision, not two. Past a skipped slot everything is
/// delivered on top of a gap, and persisting past that gap would make the skip
/// survive restarts, so the floor has to stop moving and stay stopped. Holding
/// them in one value is what makes "skipping while still persisting", which
/// would quietly restore that bug, unrepresentable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SkipPolicy {
    /// Nothing has been given up on: deliver everything and move the floor.
    #[default]
    DeliverAll,
    /// Read past this slot, and stop moving the floor.
    Skipping(Slot),
    /// A slot was skipped earlier in this run. Nothing is being skipped now, but
    /// everything read from here sits above the gap, so the floor stays put.
    FloorFrozen,
}

/// Why one pass over a peer's stream ended.
///
/// A pass that gave up inside a slot says which kind of failure did it. Only a
/// block this node cannot decode is a reason to eventually read past a slot;
/// a delivery that could not be recorded or handed off is our own problem, and
/// counting it towards the decode budget would read past a slot that is fine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PassOutcome {
    /// The stream drained.
    Drained,
    /// Ended inside this slot: its block would not deserialize.
    Undecodable(Slot),
    /// Ended inside this slot: a delivery could not be recorded or enqueued.
    Undelivered(Slot),
}

/// The pass-to-pass state of one watcher: what it is stuck on, and what it is
/// allowed to do about it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct WatcherState {
    /// The slot the watcher is stuck on and how many passes it has spent there.
    /// Keyed by slot so a failure at a new slot does not inherit an older
    /// slot's count.
    stalled: Option<(Slot, u32)>,
    skip: SkipPolicy,
}

impl SkipPolicy {
    /// The slot this pass reads past rather than stalling on.
    const fn skip_slot(self) -> Option<Slot> {
        match self {
            Self::Skipping(slot) => Some(slot),
            Self::DeliverAll | Self::FloorFrozen => None,
        }
    }

    /// Whether this pass may still move the durable delivery floor.
    const fn persists_floor(self) -> bool {
        matches!(self, Self::DeliverAll)
    }

    /// The policy once a pass has read past whatever it was stuck on.
    ///
    /// Nothing is being skipped any more, but a run that has skipped once keeps
    /// its floor frozen: everything from here sits above the gap, and moving the
    /// floor over it would make the skip survive a restart. Deliberately not
    /// named for clearing: it downgrades, it does not reset.
    const fn after_clean_pass(self) -> Self {
        match self {
            Self::DeliverAll => Self::DeliverAll,
            Self::Skipping(_) | Self::FloorFrozen => Self::FloorFrozen,
        }
    }

    /// Whether a pass that ended at `cursor` actually got past the slot this
    /// policy is skipping.
    ///
    /// A stream can end without reaching it: the zone-sdk ends a stream on a
    /// fetch failure exactly as on catching up. Downgrading on such a pass would
    /// disarm the skip before it was ever used, and the slot would have to be
    /// given up on again from scratch, so a peer endpoint that is flaky around
    /// one bad slot would never be read past.
    fn used_its_skip(self, cursor: Option<Slot>) -> bool {
        match self {
            Self::Skipping(slot) => cursor.is_some_and(|read_to| read_to >= slot),
            Self::DeliverAll | Self::FloorFrozen => true,
        }
    }
}

impl WatcherState {
    /// Folds one pass's outcome in, returning a slot the watcher has just given
    /// up on so the caller can report it.
    ///
    /// `cursor` is the read position after the pass. It is what tells a stream
    /// that truncated early apart from one that genuinely drained: the zone-sdk
    /// ends a stream on a fetch failure exactly as it does on catching up, so
    /// without this a flaky peer endpoint would reset the retry count for ever
    /// and the watcher would never escape a slot it cannot decode.
    fn after_pass(&mut self, outcome: PassOutcome, cursor: Option<Slot>) -> Option<Slot> {
        match outcome {
            PassOutcome::Undecodable(slot) => {
                let attempts = match self.stalled {
                    Some((stuck_on, attempts)) if stuck_on == slot => attempts.saturating_add(1),
                    _ => 1,
                };
                if attempts < DECODE_RETRY_LIMIT {
                    self.stalled = Some((slot, attempts));
                    return None;
                }
                // Set before the pass that reads past the bad slot, so the
                // stored floor stays below it.
                self.stalled = None;
                self.skip = SkipPolicy::Skipping(slot);
                Some(slot)
            }
            // Ours to fix, not the peer's: retry the slot without spending the
            // decode budget on it, or a store outage would read past good blocks.
            PassOutcome::Undelivered(_) => None,
            PassOutcome::Drained => {
                if self.passed_the_stall(cursor) {
                    self.stalled = None;
                }
                // Checked against the skip's own slot, not against `stalled`,
                // which arming a skip clears. Otherwise the first truncated
                // stream after arming would downgrade the skip before it had
                // read past anything.
                if self.skip.used_its_skip(cursor) {
                    self.skip = self.skip.after_clean_pass();
                }
                None
            }
        }
    }

    /// Whether the read position is now past whatever the watcher was stuck on.
    /// Vacuously true when it was not stuck.
    fn passed_the_stall(self, cursor: Option<Slot>) -> bool {
        self.stalled
            .is_none_or(|(stuck_on, _)| cursor.is_some_and(|read_to| read_to >= stuck_on))
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
    let mut cursor = match get_cross_zone_peer_floor(&dbio, peer_zone) {
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
    if let Some(slot) = cursor {
        info!(
            "Resuming watcher for peer {} from slot {slot:?}",
            hex::encode(peer_zone)
        );
    }

    // The slot the watcher is stuck on and how many passes it has spent there,
    // and the slot it has given up on. Keyed by slot so a failure at a new slot
    // does not inherit an older slot's count. Both stay in memory: a skip must
    // not outlive the process, or a peer whose blocks this build cannot decode
    // would be skipped past for good and its messages never delivered, even
    // after the decoder is fixed.
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
        let outcome = consume_peer_stream(stream, &peer, &dbio, &mut cursor, state.skip).await;

        if let Some(slot) = state.after_pass(outcome, cursor) {
            error!(
                "Watcher for peer {} could not decode slot {slot:?} after {DECODE_RETRY_LIMIT} attempts; reading past it. Messages in that block are undelivered until this node can decode it, and the delivery floor stops advancing, so every restart re-reads from {:?} onwards.",
                hex::encode(peer_zone),
                get_cross_zone_peer_floor(&dbio, peer_zone).ok().flatten()
            );
        }

        // Stream ended (caught up to the peer's last finalized block); poll again.
        tokio::time::sleep(poll_interval).await;
    }
}

/// Delivers the peer blocks carried by `stream`, moving `cursor` as it goes and
/// persisting the delivery floor behind it. Says why the pass ended, since only
/// a block this node cannot decode counts towards [`DECODE_RETRY_LIMIT`].
///
/// A block that fails to deserialize ends the pass without advancing, so the
/// next poll re-reads it and a transient failure heals. [`SkipPolicy`] names a
/// slot the caller gave up on after [`DECODE_RETRY_LIMIT`] attempts, which is
/// read past so a permanently undecodable inscription cannot wedge the watcher,
/// and says whether the floor may still move: past a skipped slot it may not,
/// because the floor is what a restart resumes from and the skipped messages
/// have to stay reachable.
async fn consume_peer_stream<S>(
    stream: S,
    peer: &PeerContext,
    dbio: &RocksDBIO,
    cursor: &mut Option<Slot>,
    skip: SkipPolicy,
) -> PassOutcome
where
    S: Stream<Item = (ZoneMessage, Slot)>,
{
    let mut stream = std::pin::pin!(stream);
    // The slot being consumed: every message of it seen so far is handled, but
    // there may be more to come, so the cursor may not advance onto it yet.
    let mut in_progress: Option<Slot> = None;

    while let Some((msg, slot)) = stream.next().await {
        if in_progress != Some(slot) {
            // A message from a later slot means the previous one completed.
            if let Some(done) = in_progress {
                advance_cursor(dbio, peer.peer_zone, cursor, done, skip.persists_floor());
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
                // Reject blocks not signed by the pinned peer key (equivocation):
                // the channel signer is authenticated by the zone-sdk, but that
                // does not prove the peer's honest sequencer produced the block.
                if peer
                    .expected_pubkey
                    .as_ref()
                    .is_some_and(|pk| !block.is_signed_by(pk))
                {
                    warn!(
                        "Watcher dropping peer {} block {}: block-signing key does not match the pinned key",
                        hex::encode(peer.peer_zone),
                        block.header.block_id
                    );
                    continue;
                }

                if !record_block_deliveries(&block, peer, dbio) {
                    // Recording a delivery is what makes it survive the mempool.
                    // Letting the pass finish here would move the floor past this
                    // slot on a store that just refused the write, and nothing
                    // re-reads a slot below the floor.
                    error!(
                        "Watcher could not record every delivery in peer {} block {}. Holding the floor and retrying the slot.",
                        hex::encode(peer.peer_zone),
                        block.header.block_id
                    );
                    return PassOutcome::Undelivered(slot);
                }
            }
            Err(err) if skip.skip_slot() == Some(slot) => {
                debug!(
                    "Watcher skipping undecodable peer {} block at slot {slot:?}: {err}",
                    hex::encode(peer.peer_zone)
                );
            }
            Err(err) => {
                error!(
                    "Watcher failed to deserialize peer {} block at slot {slot:?}: {err}. Holding the cursor and retrying.",
                    hex::encode(peer.peer_zone)
                );
                return PassOutcome::Undecodable(slot);
            }
        }
    }

    // The stream drained cleanly, so the slot in progress completed too.
    if let Some(done) = in_progress {
        advance_cursor(dbio, peer.peer_zone, cursor, done, skip.persists_floor());
    }
    PassOutcome::Drained
}

/// Moves the in-memory read cursor past `slot`, and the durable delivery floor
/// with it while `persist_floor` holds.
///
/// A persist failure is only logged: the worst case is re-reading from the last
/// stored slot after a restart, which delivery handles idempotently.
fn advance_cursor(
    dbio: &RocksDBIO,
    peer_zone: [u8; 32],
    cursor: &mut Option<Slot>,
    slot: Slot,
    persist_floor: bool,
) {
    *cursor = Some(slot);
    if !persist_floor {
        return;
    }
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
        // pass over the same slot, which the retry loop does up to
        // [`DECODE_RETRY_LIMIT`] times.
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
        let message = Message::try_new(programs::ping_sender().id(), vec![], vec![], send)
            .expect("emission serializes");
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

    /// A stream item carrying block `block_id` with one emission for this zone.
    fn peer_block_msg(block_id: u64, slot: u64) -> (ZoneMessage, Slot) {
        let block = produce_dummy_block(block_id, None, vec![emission()]);
        peer_msg(borsh::to_vec(&block).expect("block serializes"), slot)
    }

    /// A stream item carrying a block whose one emission targets
    /// `target_program_id`.
    fn peer_block_msg_to(
        block_id: u64,
        slot: u64,
        target_program_id: lee_core::program::ProgramId,
    ) -> (ZoneMessage, Slot) {
        let block = produce_dummy_block(block_id, None, vec![emission_to(target_program_id)]);
        peer_msg(borsh::to_vec(&block).expect("block serializes"), slot)
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

    fn retry_limit() -> usize {
        usize::try_from(DECODE_RETRY_LIMIT).expect("retry limit fits in usize")
    }

    fn stall(slot: u64, cursor: Option<u64>) -> (PassOutcome, Option<u64>) {
        (PassOutcome::Undecodable(Slot::from(slot)), cursor)
    }

    #[test]
    fn a_slot_is_skipped_only_after_the_retry_limit() {
        let limit = retry_limit();
        let almost = vec![stall(4, Some(3)); limit - 1];
        assert_eq!(
            run_passes(&almost).skip,
            SkipPolicy::DeliverAll,
            "a slot must not be given up on before the limit"
        );

        let enough = vec![stall(4, Some(3)); limit];
        assert_eq!(
            run_passes(&enough).skip,
            SkipPolicy::Skipping(Slot::from(4))
        );
    }

    #[test]
    fn the_floor_stays_frozen_for_the_rest_of_the_run_after_a_skip() {
        // Twenty failures at slot 4, then the pass that reads past it, then
        // clean passes: the floor must never be persistable again, or the skip
        // survives the next restart and those messages are gone for good.
        let mut passes = vec![stall(4, Some(3)); retry_limit()];
        passes.push((PassOutcome::Drained, Some(9)));
        passes.push((PassOutcome::Drained, Some(12)));
        let state = run_passes(&passes);

        assert_eq!(state.skip, SkipPolicy::FloorFrozen);
        assert!(!state.skip.persists_floor());
        assert_eq!(state.stalled, None);
    }

    #[test]
    fn a_stream_that_ended_before_the_stalled_slot_does_not_reset_the_count() {
        // The zone-sdk ends a stream on a fetch failure exactly as it does on
        // catching up. Treating that as a clean pass would reset the retry count
        // for ever, and the watcher would never escape a slot it cannot decode.
        let mut passes = vec![stall(4, Some(3)); 5];
        passes.push((PassOutcome::Drained, Some(3)));
        let state = run_passes(&passes);
        assert_eq!(
            state.stalled,
            Some((Slot::from(4), 5)),
            "the count survives a pass that never reached the stalled slot"
        );

        // Reading past it is what actually clears the stall.
        let mut read_past = vec![stall(4, Some(3)); 5];
        read_past.push((PassOutcome::Drained, Some(7)));
        assert_eq!(run_passes(&read_past).stalled, None);
    }

    #[test]
    fn a_failed_handoff_does_not_spend_the_decode_budget() {
        // A store or mempool failure is ours, not the peer's. Counting it here
        // would read past a block that decodes perfectly well.
        let passes = vec![(PassOutcome::Undelivered(Slot::from(4)), Some(3)); retry_limit() * 2];
        let state = run_passes(&passes);
        assert_eq!(state.skip, SkipPolicy::DeliverAll);
        assert_eq!(state.stalled, None);
    }

    #[test]
    fn a_truncated_pass_does_not_disarm_a_skip_before_it_is_used() {
        // Arming a skip clears `stalled`, so a `Drained` pass that never reached
        // the bad slot passes the stall check vacuously. Downgrading on that
        // would disarm the skip before it read past anything, and the slot would
        // have to be given up on again from scratch, so a peer endpoint that is
        // flaky around one bad slot would never be read past.
        let mut passes = vec![stall(4, Some(3)); retry_limit()];
        passes.push((PassOutcome::Drained, Some(3)));
        let state = run_passes(&passes);
        assert_eq!(
            state.skip,
            SkipPolicy::Skipping(Slot::from(4)),
            "a pass that ended before the skipped slot must leave the skip armed"
        );

        // The pass that actually gets past it is what downgrades.
        let mut used = vec![stall(4, Some(3)); retry_limit()];
        used.push((PassOutcome::Drained, Some(7)));
        assert_eq!(run_passes(&used).skip, SkipPolicy::FloorFrozen);
    }

    #[test]
    fn a_stall_at_a_new_slot_starts_its_own_count() {
        let passes = vec![stall(4, Some(3)), stall(4, Some(3)), stall(9, Some(8))];
        assert_eq!(run_passes(&passes).stalled, Some((Slot::from(9), 1)));
    }

    #[test]
    fn a_run_that_skipped_once_never_moves_its_floor_again() {
        // The state that makes a skip recoverable: after the bad slot is read
        // past, later passes decode cleanly, and the floor still must not move
        // over the gap or the skip survives the next restart.
        assert_eq!(
            SkipPolicy::Skipping(Slot::from(4)).after_clean_pass(),
            SkipPolicy::FloorFrozen
        );
        assert_eq!(
            SkipPolicy::FloorFrozen.after_clean_pass(),
            SkipPolicy::FloorFrozen
        );
        assert!(!SkipPolicy::FloorFrozen.persists_floor());
        assert_eq!(SkipPolicy::FloorFrozen.skip_slot(), None);

        // A run that has never skipped keeps moving.
        assert_eq!(
            SkipPolicy::DeliverAll.after_clean_pass(),
            SkipPolicy::DeliverAll
        );
        assert!(SkipPolicy::DeliverAll.persists_floor());
    }

    #[tokio::test]
    async fn watcher_persists_its_cursor_as_it_consumes() {
        let (_dir, dbio) = store();
        let mut cursor = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 0), peer_block_msg(2, 1)]),
            &peer_context(),
            &dbio,
            &mut cursor,
            SkipPolicy::DeliverAll,
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

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg_to(
                1,
                0,
                programs::wrapped_token().id(),
            )]),
            &peer_context(),
            &dbio,
            &mut cursor,
            SkipPolicy::DeliverAll,
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

        consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 0)]),
            &peer_context(),
            &dbio,
            &mut cursor,
            SkipPolicy::DeliverAll,
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

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 0)]),
            &peer_context(),
            &dbio,
            &mut cursor,
            SkipPolicy::DeliverAll,
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
    }

    #[tokio::test]
    async fn watcher_resumes_from_the_persisted_cursor_without_rereading() {
        let (_dir, dbio) = store();
        let mut cursor = None;

        consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 0), peer_block_msg(2, 1)]),
            &peer_context(),
            &dbio,
            &mut cursor,
            SkipPolicy::DeliverAll,
        )
        .await;
        assert_eq!(recorded_keys(&dbio).len(), 2);

        // Restart: a fresh watcher seeds its cursor from the store rather than
        // starting at `None`, which is what stops it re-reading the peer channel
        // from genesis.
        let resumed = get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap();
        assert_eq!(resumed, Some(Slot::from(1)));

        // The sdk resumes the stream at cursor + 1, so only block 3 arrives.
        let mut resumed_cursor = resumed;
        consume_peer_stream(
            stream::iter(vec![peer_block_msg(3, 2)]),
            &peer_context(),
            &dbio,
            &mut resumed_cursor,
            SkipPolicy::DeliverAll,
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

        let outcome = consume_peer_stream(
            stream::iter(vec![
                peer_block_msg(1, 0),
                undecodable_msg(1),
                peer_block_msg(3, 2),
            ]),
            &peer_context(),
            &dbio,
            &mut cursor,
            SkipPolicy::DeliverAll,
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

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 4), undecodable_msg(4)]),
            &peer_context(),
            &dbio,
            &mut cursor,
            SkipPolicy::DeliverAll,
        )
        .await;

        assert_eq!(outcome, PassOutcome::Undecodable(Slot::from(4)));
        assert_eq!(cursor, None, "slot 4 is re-read whole on the next pass");
        assert_eq!(get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap(), None);
        assert_eq!(recorded_keys(&dbio), vec![message_key(&PEER_ZONE, 1, 0)]);
    }

    #[tokio::test]
    async fn watcher_reads_past_a_slot_it_has_given_up_on() {
        let (_dir, dbio) = store();
        let mut cursor = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![
                peer_block_msg(1, 0),
                undecodable_msg(1),
                peer_block_msg(3, 2),
            ]),
            &peer_context(),
            &dbio,
            &mut cursor,
            SkipPolicy::Skipping(Slot::from(1)),
        )
        .await;

        assert_eq!(outcome, PassOutcome::Drained, "the pass drains");
        assert_eq!(
            recorded_keys(&dbio),
            vec![message_key(&PEER_ZONE, 1, 0), message_key(&PEER_ZONE, 3, 0)],
            "only the skipped block goes unrecorded"
        );

        // The cursor moves so later blocks are still read, but the durable floor
        // does not follow it past the gap.
        assert_eq!(
            cursor,
            Some(Slot::from(2)),
            "the pass keeps reading forward"
        );
        assert_eq!(
            get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap(),
            None,
            "the floor must not move past a slot this node could not decode"
        );
    }

    #[tokio::test]
    async fn a_restart_re_reads_a_skipped_slot() {
        let (_dir, dbio) = store();
        let mut cursor = None;

        // Slot 0 is recorded, slot 1 is undecodable and eventually skipped, slot
        // 2 is recorded on top of the gap.
        consume_peer_stream(
            stream::iter(vec![peer_block_msg(1, 0)]),
            &peer_context(),
            &dbio,
            &mut cursor,
            SkipPolicy::DeliverAll,
        )
        .await;
        consume_peer_stream(
            stream::iter(vec![undecodable_msg(1), peer_block_msg(3, 2)]),
            &peer_context(),
            &dbio,
            &mut cursor,
            SkipPolicy::Skipping(Slot::from(1)),
        )
        .await;
        assert_eq!(recorded_keys(&dbio).len(), 2);

        // A fresh watcher seeds from the floor, so slot 1 comes back around
        // rather than being skipped for the life of the store. That is what
        // makes a decoder fix recover the messages instead of a store reset.
        let resumed = get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap();
        assert_eq!(resumed, Some(Slot::from(0)));

        let mut resumed_cursor = resumed;
        consume_peer_stream(
            stream::iter(vec![peer_block_msg(2, 1), peer_block_msg(3, 2)]),
            &peer_context(),
            &dbio,
            &mut resumed_cursor,
            SkipPolicy::DeliverAll,
        )
        .await;

        // Three records, not four: the block at slot 2 was recorded on the
        // earlier pass and the re-read does not double-track it, while the block
        // at slot 1, skipped before, is recorded for the first time.
        assert_eq!(
            recorded_keys(&dbio),
            vec![
                message_key(&PEER_ZONE, 1, 0),
                message_key(&PEER_ZONE, 3, 0),
                message_key(&PEER_ZONE, 2, 0)
            ],
            "the previously skipped block must be recorded after a restart, and nothing re-recorded"
        );
        assert_eq!(
            get_cross_zone_peer_floor(&dbio, PEER_ZONE).unwrap(),
            Some(Slot::from(2)),
            "with the gap filled the floor moves again"
        );
    }
}
