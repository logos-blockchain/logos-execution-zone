use std::time::Duration;

use anyhow::{Context as _, Result};
use chain_state::zone_indexer::stop_at_read_error;
use common::{
    HashType,
    block::{Block, PeerChainTip},
    transaction::LeeTransaction,
};
use cross_zone::{
    CommitteeFloorState, FloorVerdict, Link, OutboundSource, StallState, alerts_at, build_dispatch,
    is_sequencer_only_program, link_to_tip, log_equivocation, screen_peer_block,
};
use cross_zone_inbox_core::message_key;
use futures::{Stream, StreamExt as _, TryStreamExt as _};
use kameo::actor::ActorRef;
use sequencer_bedrock_actor::{
    BedrockActorTrait,
    protocol::{AccreditedKeys, ChannelId, GetAccreditedKeys, ReadChannel, Slot, ZoneMessage},
};
use sequencer_storage_actor::{
    StorageActorTrait,
    protocol::{
        AddPendingCrossZoneDispatches, DeleteCrossZonePeerFloor, GetCrossZonePeerFloorBytes,
        GetCrossZonePeerTip, GetPendingCrossZoneDispatchCount, PeerZoneKey,
        PendingCrossZoneDispatchRecord, SetCrossZonePeerFloorBytes, SetCrossZonePeerTip,
    },
};
use sharding_pool_actor::ShardingPoolActor;
use tracing::{Instrument as _, debug, error, info, warn};

use crate::{config::CrossZoneConfig, task_group::TaskGroup};

/// The span a watcher runs in for as long as it watches its peer.
pub const WATCHER_SPAN: &str = "cross_zone_watcher";

struct PeerContext {
    peer_zone: [u8; 32],
    self_zone: [u8; 32],
    min_committee_size: u32,
    genesis_hash: Option<HashType>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PassOutcome {
    Drained,
    Stranded,
    Undecodable(Slot),
    Undelivered(Slot),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WatcherState {
    stall: StallState<Slot>,
    stranded: u32,
    committee_floor: CommitteeFloorState,
}

impl WatcherState {
    fn new(min_committee_size: u32) -> Self {
        Self {
            stall: StallState::default(),
            stranded: 0,
            committee_floor: CommitteeFloorState::new(min_committee_size),
        }
    }

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

#[derive(Debug, PartialEq, Eq)]
struct Resume {
    cursor: Option<Slot>,
    clear_floor: bool,
}

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

async fn get_cross_zone_peer_floor<S: StorageActorTrait>(
    storage_ref: &ActorRef<S>,
    peer_zone: PeerZoneKey,
) -> Result<Option<Slot>> {
    let Some(bytes) = storage_ref
        .ask(GetCrossZonePeerFloorBytes { peer_zone })
        .await?
    else {
        return Ok(None);
    };
    let bytes: [u8; 8] = bytes.as_slice().try_into().with_context(|| {
        format!(
            "Stored cross-zone peer floor is {} bytes, expected 8",
            bytes.len()
        )
    })?;
    Ok(Some(Slot::new(u64::from_le_bytes(bytes))))
}

async fn set_cross_zone_peer_floor<S: StorageActorTrait>(
    storage_ref: &ActorRef<S>,
    peer_zone: PeerZoneKey,
    floor: Slot,
) -> Result<()> {
    storage_ref
        .ask(SetCrossZonePeerFloorBytes {
            peer_zone,
            bytes: floor.to_le_bytes().to_vec(),
        })
        .await?;
    Ok(())
}

fn warn_if_pin_unevaluated(peer: &PeerContext, tip: Option<&PeerChainTip>) {
    if peer.genesis_hash.is_some() && tip.is_some() {
        warn!(
            "Watcher has a genesis pin configured but is already anchored; the pin applies only if \
             the watcher re-anchors"
        );
    }
}

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
#[must_use]
pub fn spawn_watchers<S: StorageActorTrait, B: BedrockActorTrait>(
    self_channel_id: ChannelId,
    cross_zone: &CrossZoneConfig,
    poll_interval: Duration,
    storage_ref: &ActorRef<S>,
    bedrock_pool_ref: &ActorRef<ShardingPoolActor<B, ChannelId>>,
) -> TaskGroup {
    let self_zone: [u8; 32] = *self_channel_id.as_ref();
    let mut tasks = Vec::new();

    for peer in cross_zone.peers.clone() {
        sequencer_core_metrics::record_cross_zone_peer_committee_suspended(
            hex::encode(peer.channel_id),
            false,
        );
        sequencer_core_metrics::record_cross_zone_watcher_alive(hex::encode(peer.channel_id), true);
        let span = tracing::error_span!(WATCHER_SPAN, peer_zone = %hex::encode(peer.channel_id));
        tasks.push(tokio::spawn(
            watch_peer(
                PeerContext {
                    peer_zone: peer.channel_id,
                    self_zone,
                    min_committee_size: peer.min_committee_size,
                    genesis_hash: peer.genesis_hash,
                },
                poll_interval,
                storage_ref.clone(),
                bedrock_pool_ref.clone(),
            )
            .instrument(span),
        ));
    }

    TaskGroup::new(tasks)
}

#[expect(
    clippy::infinite_loop,
    reason = "the peer watcher runs for the lifetime of the sequencer process"
)]
async fn watch_peer<S: StorageActorTrait, B: BedrockActorTrait>(
    peer: PeerContext,
    poll_interval: Duration,
    storage_ref: ActorRef<S>,
    bedrock_pool_ref: ActorRef<ShardingPoolActor<B, ChannelId>>,
) {
    let peer_zone = peer.peer_zone;
    let peer_channel_id = ChannelId::from(peer_zone);
    info!("Cross-zone watcher started");

    let floor = match get_cross_zone_peer_floor(&storage_ref, peer_zone).await {
        Ok(floor) => floor,
        Err(err) => {
            error!(
                error = format_args!("{err:#}"),
                "Watcher failed to load the stored delivery floor. Stopping this watcher rather \
                 than re-reading the channel from the beginning."
            );
            sequencer_core_metrics::record_cross_zone_watcher_alive(hex::encode(peer_zone), false);
            return;
        }
    };
    let mut tip = match storage_ref.ask(GetCrossZonePeerTip { peer_zone }).await {
        Ok(tip) => tip,
        Err(err) => {
            error!(
                error = format_args!("{err:#}"),
                "Watcher failed to load the stored chain tip. Stopping this watcher rather than \
                 accepting blocks with nothing to link them against."
            );
            sequencer_core_metrics::record_cross_zone_watcher_alive(hex::encode(peer_zone), false);
            return;
        }
    };
    warn_if_pin_unevaluated(&peer, tip.as_ref());
    let resume = resume_from(tip, floor);
    if resume.clear_floor {
        error!(
            "Watcher holds a delivery floor but no chain tip, so it cannot tell which block \
             continues that peer's chain. Re-reading the channel from the peer's genesis block; \
             deliveries already recorded are deduplicated by message key."
        );
        if let Err(err) = clear_cross_zone_peer_floor(&storage_ref, peer_zone).await {
            error!(
                error = format_args!("{err:#}"),
                "Watcher could not clear the stale delivery floor. Stopping this watcher rather \
                 than rebuilding its chain against a floor a restart would resume from."
            );
            sequencer_core_metrics::record_cross_zone_watcher_alive(hex::encode(peer_zone), false);
            return;
        }
    }
    let mut cursor = resume.cursor;
    if let Some(slot) = cursor {
        info!(slot = slot.into_inner(), "Resuming watcher");
    }

    let mut state = WatcherState::new(peer.min_committee_size);
    loop {
        if held_below_committee_floor(&mut state.committee_floor, &peer, &bedrock_pool_ref).await {
            tokio::time::sleep(poll_interval).await;
            continue;
        }
        let pass = tracing::info_span!("cross_zone_pass");
        let read = bedrock_pool_ref
            .ask(ReadChannel {
                channel_id: peer_channel_id,
                after: cursor,
            })
            .into_future()
            .instrument(pass.clone())
            .await;
        let stream = match read {
            Ok(stream) => stream,
            Err(err) => {
                pass.in_scope(|| {
                    error!(
                        error = format_args!("{err:#}"),
                        "Watcher failed to read the peer channel"
                    );
                });
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };
        let stream = stop_at_read_error(stream.map_err(anyhow::Error::from), pass.clone());
        async {
            let outcome =
                consume_peer_stream(stream, &peer, &storage_ref, &mut cursor, &mut tip).await;
            report_pass_alerts(&mut state, outcome, cursor, tip, peer_zone, &storage_ref).await;
        }
        .instrument(pass)
        .await;

        tokio::time::sleep(poll_interval).await;
    }
}

async fn report_pass_alerts<S: StorageActorTrait>(
    state: &mut WatcherState,
    outcome: PassOutcome,
    cursor: Option<Slot>,
    tip: Option<PeerChainTip>,
    peer_zone: [u8; 32],
    storage_ref: &ActorRef<S>,
) {
    if let Some((slot, attempts)) = state.after_pass(outcome, cursor)
        && alerts_at(attempts)
    {
        let floor = get_cross_zone_peer_floor(storage_ref, peer_zone)
            .await
            .ok()
            .flatten();
        error!(
            slot = slot.into_inner(),
            passes = attempts,
            floor = floor.map(Slot::into_inner),
            "Watcher is stuck at a slot. Nothing from that peer is being delivered until it \
             clears, and the delivery floor stays put so the slot keeps coming back."
        );
    }
    if alerts_at(state.stranded) {
        error!(
            passes = state.stranded,
            tip = tip.map(|held| held.block_id),
            "Watcher has read consecutive passes without placing a block on the chain it has \
             delivered from. Nothing from that peer is being delivered, and the blocks passed \
             over are already below the delivery floor."
        );
    }
}

async fn held_below_committee_floor<B: BedrockActorTrait>(
    floor: &mut CommitteeFloorState,
    peer: &PeerContext,
    bedrock_pool_ref: &ActorRef<ShardingPoolActor<B, ChannelId>>,
) -> bool {
    if !floor.enforced() {
        return false;
    }
    let read = peer_committee(bedrock_pool_ref, peer.peer_zone).await;
    match floor.after_read(read) {
        FloorVerdict::Suspended { passes, last_read } => {
            sequencer_core_metrics::record_cross_zone_peer_committee_suspended(
                hex::encode(peer.peer_zone),
                true,
            );
            if passes == 1 || alerts_at(passes) {
                error!(
                    passes,
                    committee = %describe_committee(last_read),
                    min_committee_size = peer.min_committee_size,
                    "Watcher suspended: peer committee below the floor. Nothing new is read from \
                     that peer until its committee recovers; dispatches already recorded still \
                     drain into blocks."
                );
            }
            true
        }
        FloorVerdict::Active { resumed: true } => {
            sequencer_core_metrics::record_cross_zone_peer_committee_suspended(
                hex::encode(peer.peer_zone),
                false,
            );
            info!(
                min_committee_size = peer.min_committee_size,
                "Watcher resumed: peer committee back at or above the floor"
            );
            false
        }
        FloorVerdict::Active { resumed: false } => false,
    }
}

async fn peer_committee<B: BedrockActorTrait>(
    bedrock_pool_ref: &ActorRef<ShardingPoolActor<B, ChannelId>>,
    peer_zone: [u8; 32],
) -> Option<(usize, u64)> {
    let AccreditedKeys { keys, tip_slot, .. } = bedrock_pool_ref
        .ask(GetAccreditedKeys {
            channel_id: ChannelId::from(peer_zone),
        })
        .await
        .ok()??;
    Some((keys.len(), tip_slot.into_inner()))
}

fn describe_committee(last_read: Option<(usize, u64)>) -> String {
    match last_read {
        Some((size, tip_slot)) => {
            format!("{size} accredited keys last seen at channel tip slot {tip_slot}")
        }
        None => "size unknown, channel state never read".to_owned(),
    }
}

async fn consume_peer_stream<Str, S: StorageActorTrait>(
    stream: Str,
    peer: &PeerContext,
    storage_ref: &ActorRef<S>,
    cursor: &mut Option<Slot>,
    tip: &mut Option<PeerChainTip>,
) -> PassOutcome
where
    Str: Stream<Item = (ZoneMessage, Slot)>,
{
    let mut stream = std::pin::pin!(stream);
    let mut in_progress: Option<Slot> = None;
    let mut placed = 0_usize;
    let mut skipped = 0_usize;

    while let Some((msg, slot)) = stream.next().await {
        if in_progress != Some(slot) {
            if let Some(done) = in_progress {
                advance_cursor(storage_ref, peer.peer_zone, cursor, done).await;
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
                    block_id = block.header.block_id,
                    "Watcher observed finalized peer block"
                );
                let link = match screen_peer_block(&block) {
                    Ok(recomputed) => {
                        link_to_tip(tip.as_ref(), &block, recomputed, peer.genesis_hash)
                    }
                    Err(refusal) => {
                        skipped = skipped.saturating_add(1);
                        warn!(
                            slot = slot.into_inner(),
                            reason = %refusal,
                            "Watcher not delivering from peer block. Reading on; the peer's next \
                             block that continues the chain still delivers."
                        );
                        continue;
                    }
                };
                match link {
                    Link::AlreadySeen { equivocates } => {
                        if equivocates && let Some(held) = *tip {
                            log_equivocation(
                                &peer.peer_zone,
                                block.header.block_id,
                                held.block_hash,
                                block.header.hash,
                            );
                        } else {
                            debug!(
                                block_id = block.header.block_id,
                                "Watcher ignoring peer block at or below the block it has already \
                                 delivered from"
                            );
                        }
                    }
                    Link::OffChain(reason) => {
                        skipped = skipped.saturating_add(1);
                        warn!(
                            slot = slot.into_inner(),
                            %reason,
                            "Watcher not delivering from peer block. Reading on; the peer's next \
                             block that continues the chain still delivers."
                        );
                    }
                    Link::Next(block_hash) => {
                        if !record_block_deliveries(&block, block_hash, peer, storage_ref).await {
                            error!(
                                block_id = block.header.block_id,
                                "Watcher could not record every delivery in peer block. Holding \
                                 the floor and retrying the slot."
                            );
                            return PassOutcome::Undelivered(slot);
                        }
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
                            error!(
                                block_id = block.header.block_id,
                                error = format_args!("{err:#}"),
                                "Watcher could not store the chain tip. Holding the floor and \
                                 retrying the slot."
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
                    slot = slot.into_inner(),
                    error = %err,
                    "Watcher failed to deserialize peer block. Holding the cursor and retrying."
                );
                return PassOutcome::Undecodable(slot);
            }
        }
    }

    if let Some(done) = in_progress {
        advance_cursor(storage_ref, peer.peer_zone, cursor, done).await;
    }
    if placed == 0 && skipped > 0 {
        return PassOutcome::Stranded;
    }
    PassOutcome::Drained
}

async fn advance_cursor<S: StorageActorTrait>(
    storage_ref: &ActorRef<S>,
    peer_zone: [u8; 32],
    cursor: &mut Option<Slot>,
    slot: Slot,
) {
    *cursor = Some(slot);
    if let Err(err) = set_cross_zone_peer_floor(storage_ref, peer_zone, slot).await {
        warn!(
            error = format_args!("{err:#}"),
            "Failed to persist watcher delivery floor"
        );
    }
}

/// Sets the pending-dispatch gauge from the store, so it follows the list.
pub(crate) async fn record_pending_dispatch_gauge<S: StorageActorTrait>(storage_ref: &ActorRef<S>) {
    match storage_ref.ask(GetPendingCrossZoneDispatchCount).await {
        Ok(pending) => sequencer_core_metrics::record_cross_zone_pending_dispatches(pending),
        Err(err) => {
            let err = anyhow::Error::from(err);
            warn!(
                error = format_args!("{err:#}"),
                "Failed to read the pending cross-zone dispatch count"
            );
        }
    }
}

async fn record_block_deliveries<S: StorageActorTrait>(
    block: &Block,
    block_hash: HashType,
    peer: &PeerContext,
    storage_ref: &ActorRef<S>,
) -> bool {
    let peer_zone = peer.peer_zone;
    let self_zone = peer.self_zone;
    let mut deliveries = Vec::new();
    for (index, message) in block.body.outbound.iter().enumerate() {
        if message.zone != self_zone {
            continue;
        }
        if is_sequencer_only_program(message.to.program_account_id) {
            warn!(
                "Watcher dropping peer message: a peer may not dispatch into a sequencer-only \
                 program"
            );
            continue;
        }

        let src_outbound_index = u32::try_from(index).expect("outbound index fits u32");
        let dispatch = build_dispatch(
            &OutboundSource {
                src_zone: peer_zone,
                src_block_id: block.header.block_id,
                src_block_hash: block_hash.0,
                src_outbound_index,
            },
            message,
        );
        let dispatch = LeeTransaction::Public(dispatch);

        let key = message_key(&peer_zone, block.header.block_id, src_outbound_index);
        let encoded = match borsh::to_vec(&dispatch) {
            Ok(encoded) => encoded,
            Err(err) => {
                error!(
                    message_key = %hex::encode(key),
                    error = %err,
                    "Failed to encode cross-zone dispatch"
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
        Ok(accepted) => {
            if accepted > 0 {
                record_pending_dispatch_gauge(storage_ref).await;
                info!(
                    block_id = block.header.block_id,
                    accepted, offered, "Watcher recorded cross-zone deliveries"
                );
            } else {
                debug!(
                    block_id = block.header.block_id,
                    "Watcher already held every cross-zone delivery in peer block"
                );
            }
            true
        }
        Err(err) => {
            error!(
                block_id = block.header.block_id,
                offered,
                error = %err,
                "Failed to record the cross-zone deliveries in peer block"
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use common::test_utils::produce_dummy_block;
    use cross_zone::test_utils::{linked_chain_with_outbound, ping_outbound};
    use futures::stream;
    use kameo::{actor::Spawn as _, supervision::RestartPolicy};
    use lee::GENESIS_BLOCK_ID;
    use logos_blockchain_core::mantle::ops::channel::{MsgId, inscribe::Inscription};
    use logos_blockchain_zone_sdk::{UnverifiedEd25519PublicKey, ZoneBlock};
    use sequencer_bedrock_actor::{error::Error as BedrockError, mock::MockBedrockActor};
    use sequencer_storage_actor::{
        StorageActor,
        mock::MockStorageActor,
        protocol::{AtomicUpdate, CrossZoneMessageKey, GetPendingCrossZoneDispatches},
    };
    use sharding_pool_actor::RestartConfig;
    use tempfile::TempDir;

    use super::*;

    const SELF_ZONE: [u8; 32] = [1; 32];
    const PEER_ZONE: [u8; 32] = [2; 32];

    fn peer_context() -> PeerContext {
        PeerContext {
            peer_zone: PEER_ZONE,
            self_zone: SELF_ZONE,
            min_committee_size: 0,
            genesis_hash: None,
        }
    }

    fn unreachable_bedrock_pool() -> ActorRef<ShardingPoolActor<MockBedrockActor, ChannelId>> {
        ShardingPoolActor::spawn(ShardingPoolActor::new(
            RestartConfig {
                policy: RestartPolicy::Never,
                limit: 0,
                within: Duration::ZERO,
            },
            |_channel_id| {
                let mut mock = MockBedrockActor::default();
                mock.expect_handle_get_accredited_keys()
                    .returning(|_msg, _ctx| {
                        Err(BedrockError::NodeRequestFailed(anyhow::anyhow!(
                            "node unreachable"
                        )))
                    });
                mock
            },
        ))
    }

    #[tokio::test]
    async fn the_floor_gate_fails_closed_on_an_unreachable_node() {
        let bedrock_pool_ref = unreachable_bedrock_pool();
        let peer = peer_context();
        let mut floorless = CommitteeFloorState::new(0);
        assert!(
            !held_below_committee_floor(&mut floorless, &peer, &bedrock_pool_ref).await,
            "no floor, no gate, no read"
        );

        let floored = PeerContext {
            min_committee_size: 3,
            ..peer_context()
        };
        let mut floor = CommitteeFloorState::new(floored.min_committee_size);
        assert!(
            held_below_committee_floor(&mut floor, &floored, &bedrock_pool_ref).await,
            "an unreadable committee before the first read suspends"
        );
    }

    async fn store() -> (TempDir, ActorRef<StorageActor>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let storage_ref = StorageActor::spawn(StorageActor::new(dir.path()).expect("open storage"));
        seed_genesis(&storage_ref).await;
        (dir, storage_ref)
    }

    async fn seed_genesis(storage_ref: &ActorRef<StorageActor>) {
        storage_ref
            .ask(AtomicUpdate::from_block(
                produce_dummy_block(0, None, vec![]),
                Arc::new(lee::V03State::new()),
                Vec::new(),
            ))
            .await
            .expect("seed genesis");
    }

    fn outbound() -> lee::OutboundMessage {
        ping_outbound(SELF_ZONE, b"hi")
    }

    fn outbound_to(target_program_id: lee_core::account::AccountId) -> lee::OutboundMessage {
        lee::OutboundMessage {
            to: lee::Actor::new(target_program_id, target_program_id),
            ..outbound()
        }
    }

    fn peer_msg(data: Vec<u8>, slot: u64) -> (ZoneMessage, Slot) {
        (
            ZoneMessage::Block(ZoneBlock {
                id: MsgId::from([0; 32]),
                data: Inscription::new_unchecked(data),
                signer: UnverifiedEd25519PublicKey::from_bytes(&[0; 32]).expect("valid key"),
            }),
            Slot::from(slot),
        )
    }

    fn chain_to(block_id: u64) -> Vec<Block> {
        linked_chain_with_outbound(block_id, |_| vec![outbound()])
    }

    fn chain_block(block_id: u64) -> Block {
        chain_to(block_id).pop().expect("chain reaches block_id")
    }

    fn chain_hash(block_id: u64) -> HashType {
        chain_block(block_id).header.hash
    }

    fn chain_block_to(block_id: u64, target_program_id: lee_core::account::AccountId) -> Block {
        let prefix = chain_to(block_id.saturating_sub(1));
        common::test_utils::produce_dummy_block_with_outbound(
            block_id,
            prefix.last().map(|block| block.header.hash),
            vec![outbound_to(target_program_id)],
        )
    }

    fn block_msg(block: &Block, slot: u64) -> (ZoneMessage, Slot) {
        peer_msg(borsh::to_vec(block).expect("block serializes"), slot)
    }

    fn peer_block_msg(block_id: u64, slot: u64) -> (ZoneMessage, Slot) {
        block_msg(&chain_block(block_id), slot)
    }

    fn peer_block_msg_without_outbound(block_id: u64, slot: u64) -> (ZoneMessage, Slot) {
        let prefix = chain_to(block_id.saturating_sub(1));
        let block = produce_dummy_block(
            block_id,
            prefix.last().map(|block| block.header.hash),
            vec![],
        );
        block_msg(&block, slot)
    }

    fn peer_block_msg_to(
        block_id: u64,
        slot: u64,
        target_program_id: lee_core::account::AccountId,
    ) -> (ZoneMessage, Slot) {
        block_msg(&chain_block_to(block_id, target_program_id), slot)
    }

    fn tip_at(block_id: u64) -> PeerChainTip {
        PeerChainTip {
            block_id,
            block_hash: chain_hash(block_id),
        }
    }

    fn undecodable_msg(slot: u64) -> (ZoneMessage, Slot) {
        peer_msg(b"not a block".to_vec(), slot)
    }

    async fn recorded_keys(storage_ref: &ActorRef<StorageActor>) -> Vec<CrossZoneMessageKey> {
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

    fn store_refusing_deliveries() -> ActorRef<MockStorageActor> {
        let floor: Arc<Mutex<Option<Vec<u8>>>> = Arc::default();
        let tip: Arc<Mutex<Option<PeerChainTip>>> = Arc::default();
        let mut storage = MockStorageActor::new();

        storage
            .expect_handle_add_pending_cross_zone_dispatches()
            .returning(|_, _| {
                Err(sequencer_storage_actor::error::Error::DatabaseError(
                    anyhow::anyhow!("the store refused the write"),
                ))
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

    fn run_passes(passes: &[(PassOutcome, Option<u64>)]) -> WatcherState {
        let mut state = WatcherState::new(0);
        for (outcome, cursor) in passes {
            state.after_pass(*outcome, cursor.map(Slot::from));
        }
        state
    }

    #[test]
    fn passes_that_place_nothing_while_skipping_blocks_are_counted() {
        let stranded = [
            (PassOutcome::Stranded, Some(4)),
            (PassOutcome::Stranded, Some(9)),
            (PassOutcome::Stranded, Some(14)),
        ];
        assert_eq!(run_passes(&stranded).stranded, 3);

        let mut recovered = stranded.to_vec();
        recovered.push((PassOutcome::Drained, Some(19)));
        assert_eq!(run_passes(&recovered).stranded, 0);

        assert_eq!(run_passes(&[(PassOutcome::Drained, Some(4))]).stranded, 0);
    }

    #[test]
    fn every_way_of_ending_early_keeps_the_slot_coming_back() {
        for outcome in [
            PassOutcome::Undecodable(Slot::from(4)),
            PassOutcome::Undelivered(Slot::from(4)),
        ] {
            let mut state = WatcherState::new(0);
            assert_eq!(
                state.after_pass(outcome, Some(Slot::from(3))),
                Some((Slot::from(4), 1))
            );
        }
    }

    #[test]
    fn a_floor_without_a_tip_resumes_from_the_peers_genesis() {
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
        assert_eq!(cursor, Some(Slot::from(1)));
        assert_eq!(
            get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                .await
                .unwrap(),
            Some(Slot::from(1)),
            "the cursor must be durable, not just in memory"
        );
        let mut expected = vec![message_key(&PEER_ZONE, 1, 0), message_key(&PEER_ZONE, 2, 0)];
        expected.sort_unstable();
        assert_eq!(recorded_keys(&storage_ref).await, expected);
    }

    #[tokio::test]
    async fn a_reverted_emission_is_never_recorded() {
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg_without_outbound(1, 0)]),
            &peer_context(),
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(outcome, PassOutcome::Drained);
        assert!(
            recorded_keys(&storage_ref).await.is_empty(),
            "an emission whose transaction reverted must not be delivered"
        );
    }

    #[tokio::test]
    async fn a_delivery_into_a_sequencer_only_program_is_never_recorded() {
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg_to(
                1,
                0,
                programs::cross_zone_inbox_account_id(),
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
        assert_eq!(
            get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                .await
                .unwrap(),
            Some(Slot::from(0)),
            "the slot was fully read, so the floor still advances"
        );
    }

    #[tokio::test]
    async fn a_delivery_into_the_fee_program_is_never_recorded() {
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg_to(1, 0, programs::fee_account_id())]),
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
            "a message aimed at the fee program must not be recorded"
        );
        assert_eq!(
            get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                .await
                .unwrap(),
            Some(Slot::from(0)),
            "the slot was fully read, so the floor still advances"
        );
    }

    #[tokio::test]
    async fn a_delivery_to_an_unrelated_target_is_still_recorded() {
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg_to(
                1,
                0,
                programs::wrapped_token_account_id(),
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
        let Ok(cross_zone_inbox_core::Message::Dispatch(msg)) =
            borsh::from_slice(&public_tx.message().execution.root.message)
        else {
            panic!("the recorded transaction is an inbox dispatch");
        };

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

        assert_eq!(outcome, PassOutcome::Undelivered(Slot::from(0)));
        assert_eq!(
            get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                .await
                .unwrap(),
            None,
            "the slot must stay re-readable"
        );
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

        let resumed = get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
            .await
            .unwrap();
        assert_eq!(resumed, Some(Slot::from(1)));
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
        assert_eq!(
            get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                .await
                .unwrap(),
            Some(Slot::from(2))
        );
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

        assert_eq!(outcome, PassOutcome::Undecodable(Slot::from(1)));
        assert_eq!(
            get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                .await
                .unwrap(),
            Some(Slot::from(0))
        );
        assert_eq!(
            recorded_keys(&storage_ref).await,
            vec![message_key(&PEER_ZONE, 1, 0)],
            "the block after the failure is unread"
        );
    }

    #[tokio::test]
    async fn watcher_does_not_persist_inside_a_partially_failed_slot() {
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
        assert_eq!(cursor, None, "slot 4 is re-read whole on the next pass");
        assert_eq!(
            get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            recorded_keys(&storage_ref).await,
            vec![message_key(&PEER_ZONE, 1, 0)]
        );
    }

    #[tokio::test]
    async fn an_undecodable_block_stops_the_peer() {
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
        assert_eq!(
            get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                .await
                .unwrap(),
            Some(Slot::from(0)),
            "the floor stays below it, so a fixed decoder recovers the messages"
        );
        assert_eq!(tip, Some(tip_at(1)));
    }

    #[tokio::test]
    async fn a_block_claiming_an_id_ahead_of_the_chain_is_not_delivered_from() {
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;
        let pre_burn =
            common::test_utils::produce_dummy_block_with_outbound(5, None, vec![outbound()]);

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
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;
        let equivocation = common::test_utils::produce_dummy_block_with_outbound(
            2,
            Some(HashType([9; 32])),
            vec![outbound()],
        );

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
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;
        let forked = common::test_utils::produce_dummy_block_with_outbound(
            2,
            Some(HashType([9; 32])),
            vec![outbound()],
        );

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
    async fn a_pinned_genesis_anchors_only_on_the_pinned_chain() {
        let (_dir, storage_ref) = store().await;
        let mut cursor = None;
        let mut tip = None;
        let pinned_elsewhere = PeerContext {
            genesis_hash: Some(HashType([9; 32])),
            ..peer_context()
        };

        let outcome = consume_peer_stream(
            stream::iter(vec![peer_block_msg(GENESIS_BLOCK_ID, 0)]),
            &pinned_elsewhere,
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(outcome, PassOutcome::Stranded);
        assert!(recorded_keys(&storage_ref).await.is_empty());
        assert_eq!(tip, None, "a genesis off the pin never anchors");

        let pinned_here = PeerContext {
            genesis_hash: Some(chain_hash(GENESIS_BLOCK_ID)),
            ..peer_context()
        };
        let anchored = consume_peer_stream(
            stream::iter(vec![peer_block_msg(GENESIS_BLOCK_ID, 1)]),
            &pinned_here,
            &storage_ref,
            &mut cursor,
            &mut tip,
        )
        .await;

        assert_eq!(anchored, PassOutcome::Drained);
        assert_eq!(
            tip,
            Some(tip_at(GENESIS_BLOCK_ID)),
            "the pinned genesis anchors"
        );
    }

    #[tokio::test]
    async fn a_tampered_header_hash_is_not_delivered_from() {
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
        let (_dir, storage_ref) = store().await;
        set_cross_zone_peer_floor(&storage_ref, PEER_ZONE, Slot::from(5000))
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
        assert_eq!(resume.cursor, None, "the rebuild reads from genesis");
        assert!(resume.clear_floor);

        clear_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
            .await
            .unwrap();
        assert_eq!(
            get_cross_zone_peer_floor(&storage_ref, PEER_ZONE)
                .await
                .unwrap(),
            None,
            "and a crash mid-rebuild resumes from genesis too, not from slot 5000"
        );
    }
}
