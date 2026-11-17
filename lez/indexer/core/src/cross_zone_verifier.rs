use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
    num::{NonZeroU32, NonZeroU64},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::anyhow;
use chain_state::{
    timeout_node::TimeoutNode,
    zone_indexer::{ZoneIndexer, stop_at_read_error},
};
use common::{
    HashType,
    block::{Block, PeerChainTip},
    transaction::LeeTransaction,
};
use cross_zone::{
    CommitteeFloorState, FloorVerdict, Link, OffChain, OutboundSource, StallState, alerts_at,
    build_dispatch, link_to_tip, log_equivocation, screen_peer_block,
};
use cross_zone_inbox_core::{
    CrossZoneMessage, Message as InboxMessage, MessageKey, ZoneId, message_key,
};
use futures::{Stream, StreamExt as _};
use lee::GENESIS_BLOCK_ID;
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use logos_blockchain_zone_sdk::{
    CommonHttpClient, Slot, ZoneMessage,
    adapter::{Node as _, NodeHttpClient},
};
use tokio::{sync::RwLock, time::Instant};
use tracing::{Instrument as _, debug, error, info, warn};

use crate::{
    config::IndexerConfig,
    status::{PeerHealth, PeerStatus},
};

const LAG_LOG_INTERVAL: Duration = Duration::from_secs(30);

const PEER_BLOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(300);

const PEER_BLOCK_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Why a cross-zone dispatch could not be verified.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CrossZoneVerifyError {
    #[error("{0}")]
    Forged(ForgedDispatch),
    #[error(
        "peer zone {} block {block_id} still unavailable after {waited:?}",
        hex::encode(zone)
    )]
    PeerUnavailable {
        zone: ZoneId,
        block_id: u64,
        waited: Duration,
    },
}

/// A dispatch judged permanently invalid: its source coordinates plus the verdict, which is what
/// the caller's halt record persists.
#[derive(Debug)]
pub struct ForgedDispatch {
    pub src_zone: ZoneId,
    pub src_block_id: u64,
    pub src_outbound_index: u32,
    pub verdict: String,
}

impl Display for ForgedDispatch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "forged cross-zone dispatch from zone {} block {} tx {}: {}",
            hex::encode(self.src_zone),
            self.src_block_id,
            self.src_outbound_index,
            self.verdict
        )
    }
}

#[derive(Debug)]
enum PeerBlockError {
    NotOnPeerChain(String),
    Unavailable { waited: Duration },
}

/// The replay key plus the source block: what the inbox treats as one delivery.
pub type SeenKey = (MessageKey, [u8; 32]);

struct PeerChain {
    blocks: HashMap<u64, (Block, Slot)>,
    evicted: HashMap<u64, (Slot, HashType)>,
    next_to_evict: u64,
    window: u64,
    verified_prefix: Option<PeerChainTip>,
    genesis_hash: Option<HashType>,
    pin_refused: bool,
}

impl PeerChain {
    fn new(window: u64, genesis_hash: Option<HashType>) -> Self {
        Self {
            blocks: HashMap::new(),
            evicted: HashMap::new(),
            next_to_evict: GENESIS_BLOCK_ID,
            window,
            verified_prefix: None,
            genesis_hash,
            pin_refused: false,
        }
    }

    fn evict_behind_window(&mut self) {
        let Some(tip) = self.verified_prefix else {
            return;
        };
        let floor = tip.block_id.saturating_sub(self.window);
        while self.next_to_evict < floor {
            if let Some((block, read_at)) = self.blocks.remove(&self.next_to_evict) {
                self.evicted
                    .insert(self.next_to_evict, (read_at, block.header.hash));
            }
            self.next_to_evict = self.next_to_evict.saturating_add(1);
        }
    }

    const fn next_expected(&self) -> u64 {
        match self.verified_prefix {
            Some(tip) => tip.block_id.saturating_add(1),
            None => GENESIS_BLOCK_ID,
        }
    }

    fn extend_prefix(&mut self) {
        while let Some((next, _)) = self.blocks.get(&self.next_expected()) {
            match link_to_tip(
                self.tip().as_ref(),
                next,
                next.header.hash,
                self.genesis_hash,
            ) {
                Link::Next(block_hash) => {
                    self.verified_prefix = Some(PeerChainTip {
                        block_id: next.header.block_id,
                        block_hash,
                    });
                }
                Link::AlreadySeen { .. } | Link::OffChain(_) => break,
            }
        }
        self.evict_behind_window();
    }

    const fn tip(&self) -> Option<PeerChainTip> {
        self.verified_prefix
    }
}

enum PeerLookup {
    Cached(Box<Block>),
    Evicted { read_at: Slot, block_hash: HashType },
    InsideRun,
    Behind,
}

#[derive(Clone)]
struct PeerBlocks {
    chains: Arc<RwLock<HashMap<ZoneId, PeerChain>>>,
    window: u64,
    genesis_pins: Arc<HashMap<ZoneId, HashType>>,
}

impl Default for PeerBlocks {
    fn default() -> Self {
        Self::new(crate::config::default_peer_block_cache_window())
    }
}

impl PeerBlocks {
    fn new(configured: NonZeroU32) -> Self {
        Self {
            chains: Arc::default(),
            window: NonZeroU64::from(configured).get(),
            genesis_pins: Arc::default(),
        }
    }

    fn with_genesis_pins(mut self, pins: HashMap<ZoneId, HashType>) -> Self {
        self.genesis_pins = Arc::new(pins);
        self
    }

    async fn insert(&self, zone: ZoneId, block: Block, read_at: Slot) -> bool {
        let mut chains = self.chains.write().await;
        let chain = chains
            .entry(zone)
            .or_insert_with(|| PeerChain::new(self.window, self.genesis_pins.get(&zone).copied()));

        let link = link_to_tip(
            chain.tip().as_ref(),
            &block,
            block.header.hash,
            chain.genesis_hash,
        );
        let continues_the_run = matches!(link, Link::Next(_));
        match link {
            Link::OffChain(off @ OffChain::WrongGenesis { .. }) => {
                chain.pin_refused = true;
                error!(
                    peer_zone = %hex::encode(zone),
                    reason = %off,
                    "Peer reader refused to anchor"
                );
                false
            }
            Link::OffChain(OffChain::NotTheGenesis { .. } | OffChain::SkipsAhead { .. }) => {
                debug!(
                    peer_zone = %hex::encode(zone),
                    block_id = block.header.block_id,
                    next_expected = chain.next_expected(),
                    "Peer reader not caching block: only the next expected one continues the run \
                     verified from that peer's genesis"
                );
                false
            }
            Link::AlreadySeen { .. } => {
                let held_hash = chain
                    .blocks
                    .get(&block.header.block_id)
                    .map(|(held, _)| held.header.hash)
                    .or_else(|| {
                        chain
                            .evicted
                            .get(&block.header.block_id)
                            .map(|&(_, block_hash)| block_hash)
                    });
                match held_hash {
                    Some(held) if held == block.header.hash => false,
                    Some(held) => {
                        log_equivocation(&zone, block.header.block_id, held, block.header.hash);
                        false
                    }
                    None => {
                        debug!(
                            peer_zone = %hex::encode(zone),
                            block_id = block.header.block_id,
                            "Peer reader not caching block: below the peer's genesis, on no chain \
                             the run can walk"
                        );
                        false
                    }
                }
            }
            Link::Next(_) | Link::OffChain(OffChain::DoesNotLink { .. }) => {
                if let Some((held, _)) = chain.blocks.get(&block.header.block_id) {
                    if held.header.hash == block.header.hash {
                        return false;
                    }
                    if !continues_the_run {
                        log_equivocation(
                            &zone,
                            block.header.block_id,
                            held.header.hash,
                            block.header.hash,
                        );
                        return false;
                    }
                    info!(
                        peer_zone = %hex::encode(zone),
                        block_id = block.header.block_id,
                        held_hash = %held.header.hash,
                        replacement_hash = %block.header.hash,
                        "Replacing held peer block with one that continues the verified run where \
                         the held one never could"
                    );
                }
                chain.blocks.insert(block.header.block_id, (block, read_at));
                chain.extend_prefix();
                true
            }
        }
    }

    async fn resolve(&self, zone: ZoneId, block_id: u64) -> PeerLookup {
        let chains = self.chains.read().await;
        let Some(chain) = chains.get(&zone) else {
            return PeerLookup::Behind;
        };
        if chain
            .verified_prefix
            .is_none_or(|tip| tip.block_id < block_id)
        {
            return PeerLookup::Behind;
        }
        if let Some((block, _)) = chain.blocks.get(&block_id) {
            return PeerLookup::Cached(Box::new(block.clone()));
        }
        chain
            .evicted
            .get(&block_id)
            .map_or(PeerLookup::InsideRun, |&(read_at, block_hash)| {
                PeerLookup::Evicted {
                    read_at,
                    block_hash,
                }
            })
    }

    #[cfg(test)]
    async fn get(&self, zone: ZoneId, block_id: u64) -> Option<Block> {
        self.chains
            .read()
            .await
            .get(&zone)
            .and_then(|chain| chain.blocks.get(&block_id).map(|(block, _)| block.clone()))
    }

    async fn verified_prefix(&self, zone: ZoneId) -> Option<u64> {
        self.chains
            .read()
            .await
            .get(&zone)
            .and_then(|chain| chain.verified_prefix)
            .map(|tip| tip.block_id)
    }

    async fn pin_refused(&self, zone: ZoneId) -> bool {
        self.chains
            .read()
            .await
            .get(&zone)
            .is_some_and(|chain| chain.pin_refused && chain.verified_prefix.is_none())
    }
}

#[derive(Clone, Copy, Debug)]
struct AbsenceEvidence {
    channel_tip_slot: u64,
    drained_passes: u64,
    verified_tip: Option<u64>,
    lib_slot: u64,
}

struct PassReport {
    cursor_slot: Option<u64>,
    verified_tip: Option<u64>,
    stuck: Option<(u64, u32)>,
    drained: bool,
    drained_at_tip: Option<u64>,
    lib_slot: Option<u64>,
    pin_refused: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ReaderHold {
    #[default]
    None,
    Suspended,
    PinRefused,
}

#[derive(Clone, Copy, Debug, Default)]
struct PeerDiagnostics {
    cursor_slot: Option<u64>,
    verified_tip: Option<u64>,
    stuck: Option<(u64, u32)>,
    last_pass_drained: bool,
    halted: bool,
    hold: ReaderHold,
    evidence: TipEvidence,
}

impl PeerDiagnostics {
    const fn health(&self) -> PeerHealth {
        if self.halted {
            return PeerHealth::Halted;
        }
        match self.hold {
            ReaderHold::PinRefused => PeerHealth::PinMismatch,
            ReaderHold::Suspended => PeerHealth::Suspended,
            ReaderHold::None => {
                if self.stuck.is_some() {
                    PeerHealth::Holed
                } else if self.last_pass_drained && self.evidence.since.is_some() {
                    PeerHealth::Live
                } else {
                    PeerHealth::Lagging
                }
            }
        }
    }
}

#[derive(Clone, Default)]
struct PeerWatch {
    peers: Arc<Mutex<HashMap<ZoneId, PeerDiagnostics>>>,
}

impl PeerWatch {
    fn confirmed_absence(
        &self,
        zone: ZoneId,
        wait_started: Instant,
        local_slot: u64,
    ) -> Option<AbsenceEvidence> {
        let peers = self.lock();
        let entry = peers.get(&zone)?;
        if entry.hold != ReaderHold::None {
            return None;
        }
        let evidence = entry.evidence;
        if evidence.since? > wait_started || evidence.latest? < wait_started {
            return None;
        }
        let lib_slot = evidence.lib_slot?;
        if lib_slot < local_slot {
            return None;
        }
        Some(AbsenceEvidence {
            channel_tip_slot: evidence.channel_tip_slot?,
            drained_passes: evidence.drained_passes,
            verified_tip: entry.verified_tip,
            lib_slot,
        })
    }

    fn is_suspended(&self, zone: ZoneId) -> bool {
        self.lock()
            .get(&zone)
            .is_some_and(|entry| entry.hold == ReaderHold::Suspended)
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<ZoneId, PeerDiagnostics>> {
        self.peers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn clear_halted(&self, zone: ZoneId) {
        self.lock().entry(zone).or_default().halted = false;
    }

    fn mark_halted(&self, zone: ZoneId) {
        self.lock().entry(zone).or_default().halted = true;
    }

    fn register(&self, zone: ZoneId) {
        self.lock().entry(zone).or_default();
    }

    fn report_failed_pass(&self, zone: ZoneId) {
        let mut peers = self.lock();
        let entry = peers.entry(zone).or_default();
        entry.hold = ReaderHold::None;
        entry.last_pass_drained = false;
        entry.evidence = TipEvidence::default();
    }

    fn report_suspended(&self, zone: ZoneId) {
        let mut peers = self.lock();
        let entry = peers.entry(zone).or_default();
        entry.hold = ReaderHold::Suspended;
        entry.last_pass_drained = false;
        entry.evidence = TipEvidence::default();
    }

    fn report_pass(&self, zone: ZoneId, report: &PassReport) {
        let mut peers = self.lock();
        let entry = peers.entry(zone).or_default();
        entry.hold = if report.pin_refused {
            ReaderHold::PinRefused
        } else {
            ReaderHold::None
        };
        entry.cursor_slot = report.cursor_slot;
        entry.verified_tip = report.verified_tip;
        entry.stuck = report.stuck;
        entry.last_pass_drained = report.drained;
        if let Some(tip_slot) = report.drained_at_tip {
            if report.pin_refused {
                entry.evidence = TipEvidence::default();
                return;
            }
            let now = Instant::now();
            if entry.evidence.since.is_none() {
                entry.evidence.since = Some(now);
            }
            entry.evidence.latest = Some(now);
            entry.evidence.drained_passes = entry.evidence.drained_passes.saturating_add(1);
            entry.evidence.channel_tip_slot = Some(tip_slot);
            entry.evidence.lib_slot = entry.evidence.lib_slot.max(report.lib_slot);
        } else {
            entry.evidence = TipEvidence::default();
        }
    }

    fn statuses(&self) -> Vec<PeerStatus> {
        let peers = self.lock();
        let mut all: Vec<PeerStatus> = peers
            .iter()
            .map(|(zone, diagnostics)| PeerStatus {
                zone: hex::encode(zone),
                verified_tip_block_id: diagnostics.verified_tip,
                cursor_slot: diagnostics.cursor_slot,
                stuck_slot_attempts: diagnostics.stuck.map_or(0, |(_, attempts)| attempts),
                health: diagnostics.health(),
            })
            .collect();
        all.sort_by(|a, b| a.zone.cmp(&b.zone));
        all
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct TipEvidence {
    since: Option<Instant>,
    latest: Option<Instant>,
    drained_passes: u64,
    channel_tip_slot: Option<u64>,
    lib_slot: Option<u64>,
}

/// Re-derives every cross-zone dispatch from the peer's finalized block and rejects it if the
/// bytes differ, so delivery does not rely on trusting the sequencer.
#[derive(Clone)]
pub struct CrossZoneVerifier {
    self_zone: ZoneId,
    peers: PeerBlocks,
    refetch_clients: HashMap<ZoneId, Arc<ZoneIndexer<TimeoutNode<NodeHttpClient>>>>,
    refetch_attempts: Arc<AtomicU64>,
    seen: Arc<RwLock<HashSet<SeenKey>>>,
    watch: PeerWatch,
}

impl CrossZoneVerifier {
    /// Builds the verifier and spawns one peer reader per configured peer.
    pub fn start(config: &IndexerConfig) -> Option<Self> {
        let cross_zone = config.cross_zone.as_ref()?;
        let self_zone: ZoneId = *config.channel_id.as_ref();
        let genesis_pins = cross_zone
            .peers
            .iter()
            .filter_map(|peer| peer.genesis_hash.map(|pinned| (peer.channel_id, pinned)))
            .collect();
        let peers = PeerBlocks::new(config.peer_block_cache_window).with_genesis_pins(genesis_pins);
        let watch = PeerWatch::default();
        let mut refetch_clients = HashMap::new();

        for peer in &cross_zone.peers {
            let node = TimeoutNode::new(NodeHttpClient::new(
                CommonHttpClient::new(config.bedrock_config.auth.clone().map(Into::into)),
                config.bedrock_config.addr.clone(),
            ));
            let tip_node = node.clone();
            refetch_clients.insert(
                peer.channel_id,
                Arc::new(ZoneIndexer::new(
                    ChannelId::from(peer.channel_id),
                    node.clone(),
                    config.backfill_batch_slots,
                )),
            );
            watch.register(peer.channel_id);
            let span = tracing::error_span!(
                "cross_zone_peer_reader",
                peer_zone = %hex::encode(peer.channel_id)
            );
            tokio::spawn(
                read_peer(
                    ZoneIndexer::new(
                        ChannelId::from(peer.channel_id),
                        node,
                        config.backfill_batch_slots,
                    ),
                    tip_node,
                    peer.channel_id,
                    peer.min_committee_size,
                    peers.clone(),
                    watch.clone(),
                    config.consensus_info_polling_interval,
                )
                .instrument(span),
            );
        }

        Some(Self {
            self_zone,
            peers,
            refetch_clients,
            refetch_attempts: Arc::new(AtomicU64::new(0)),
            seen: Arc::new(RwLock::new(HashSet::new())),
            watch,
        })
    }

    /// Per-peer reader snapshots for status reporting.
    #[must_use]
    pub fn peer_statuses(&self) -> Vec<PeerStatus> {
        self.watch.statuses()
    }

    /// The seen keys of every dispatch in `block`, decoded without any verification.
    #[must_use]
    pub fn unverified_dispatch_keys(block: &Block) -> Vec<SeenKey> {
        block
            .body
            .transactions
            .iter()
            .filter_map(|tx| Self::decode_dispatch(tx).as_ref().map(seen_key))
            .collect()
    }

    /// [`Self::unverified_dispatch_keys`] plus unsticking each dispatch's source zone from a halted
    /// mark: an operator acceptance supersedes the verdict that marked the zone.
    #[must_use]
    pub fn accept_unverified(&self, block: &Block) -> Vec<SeenKey> {
        block
            .body
            .transactions
            .iter()
            .filter_map(Self::decode_dispatch)
            .map(|msg| {
                self.watch.clear_halted(msg.src_zone);
                seen_key(&msg)
            })
            .collect()
    }

    /// Verifies every cross-zone dispatch in a block, returning the keys to mark seen, or the
    /// reason verification could not complete. `Forged` means the caller must halt ingestion;
    /// `PeerUnavailable` means it must hold its read cursor and retry.
    pub async fn verify_block(
        &self,
        block: &Block,
        inscription_slot: Slot,
    ) -> Result<Vec<SeenKey>, CrossZoneVerifyError> {
        let mut verified = Vec::new();
        for tx in &block.body.transactions {
            let Some(msg) = Self::decode_dispatch(tx) else {
                continue;
            };

            let key = seen_key(&msg);
            if self.seen.read().await.contains(&key) {
                debug!(
                    peer_zone = %hex::encode(msg.src_zone),
                    peer_block_id = msg.src_block_id,
                    peer_tx_index = msg.src_outbound_index,
                    "Skipping already-seen cross-zone dispatch, a replay the inbox refuses"
                );
                continue;
            }

            let expected = self.rederive(&msg, inscription_slot.into_inner()).await?;
            if LeeTransaction::Public(expected) != *tx {
                return Err(forged(&msg, "re-derivation mismatch".to_owned()));
            }

            info!(
                peer_zone = %hex::encode(msg.src_zone),
                peer_block_id = msg.src_block_id,
                peer_tx_index = msg.src_outbound_index,
                "Verified cross-zone dispatch"
            );
            verified.push(key);
        }
        Ok(verified)
    }

    /// Marks the given dispatch keys seen, so a later replay of them is accepted without
    /// re-derivation. Call only after the carrying block applies, or a later forged dispatch
    /// could reuse the key to skip re-derivation.
    pub async fn record_seen(&self, keys: Vec<SeenKey>) {
        if keys.is_empty() {
            return;
        }
        self.seen.write().await.extend(keys);
    }

    fn decode_dispatch(tx: &LeeTransaction) -> Option<CrossZoneMessage> {
        let (to, message) = tx.public_call()?;
        if to.program_account_id != programs::cross_zone_inbox_account_id() {
            return None;
        }
        match borsh::from_slice::<InboxMessage>(message) {
            Ok(InboxMessage::Dispatch(msg)) => Some(msg),
            Ok(InboxMessage::Mark(_) | InboxMessage::InitConfig(_)) | Err(_) => None,
        }
    }

    async fn rederive(
        &self,
        msg: &CrossZoneMessage,
        local_slot: u64,
    ) -> Result<lee::PublicTransaction, CrossZoneVerifyError> {
        let peer_block = self
            .wait_for_peer_block(msg.src_zone, msg.src_block_id, local_slot)
            .await
            .map_err(|err| match err {
                PeerBlockError::NotOnPeerChain(verdict) => forged(msg, verdict),
                PeerBlockError::Unavailable { waited } => CrossZoneVerifyError::PeerUnavailable {
                    zone: msg.src_zone,
                    block_id: msg.src_block_id,
                    waited,
                },
            })?;

        let src_outbound_index =
            usize::try_from(msg.src_outbound_index).expect("u32 index fits in usize");
        let message = peer_block
            .body
            .outbound
            .get(src_outbound_index)
            .ok_or_else(|| {
                forged(
                    msg,
                    "src_outbound_index out of range in peer block".to_owned(),
                )
            })?;

        if message.zone != self.self_zone {
            return Err(forged(
                msg,
                "peer message targets a different zone".to_owned(),
            ));
        }

        self.watch.clear_halted(msg.src_zone);

        Ok(build_dispatch(
            &OutboundSource {
                src_zone: msg.src_zone,
                src_block_id: msg.src_block_id,
                src_block_hash: peer_block.recompute_hash().0,
                src_outbound_index: msg.src_outbound_index,
            },
            message,
        ))
    }

    async fn wait_for_peer_block(
        &self,
        zone: ZoneId,
        block_id: u64,
        local_slot: u64,
    ) -> Result<Block, PeerBlockError> {
        let wait_started = Instant::now();
        let mut waited = Duration::ZERO;
        let mut refetch_failures: u32 = 0;
        loop {
            let may_escalate = match self.peers.resolve(zone, block_id).await {
                PeerLookup::Cached(block) => return Ok(*block),
                PeerLookup::Evicted {
                    read_at,
                    block_hash,
                } => {
                    match self
                        .refetch_evicted(zone, block_id, read_at, block_hash)
                        .await
                    {
                        Ok(block) => return Ok(block),
                        Err(err) => {
                            refetch_failures = refetch_failures.saturating_add(1);
                            if alerts_at(refetch_failures) {
                                error!(
                                    peer_zone = %hex::encode(zone),
                                    block_id,
                                    consecutive_failures = refetch_failures,
                                    total_refetches = self.refetch_attempts.load(Ordering::Relaxed),
                                    error = format_args!("{err:#}"),
                                    "Refetch of evicted peer block keeps failing, retrying"
                                );
                            }
                        }
                    }
                    false
                }
                PeerLookup::InsideRun => {
                    return Err(PeerBlockError::NotOnPeerChain(format!(
                        "peer zone {} chain is verified past block {block_id} but it is absent",
                        hex::encode(zone)
                    )));
                }
                PeerLookup::Behind => true,
            };
            if waited >= PEER_BLOCK_WAIT_TIMEOUT {
                if may_escalate
                    && let Some(evidence) =
                        self.watch.confirmed_absence(zone, wait_started, local_slot)
                {
                    self.watch.mark_halted(zone);
                    return Err(PeerBlockError::NotOnPeerChain(absence_verdict(
                        zone, block_id, &evidence,
                    )));
                }
                return Err(PeerBlockError::Unavailable { waited });
            }
            if may_escalate
                && !waited.is_zero()
                && waited.as_secs().is_multiple_of(LAG_LOG_INTERVAL.as_secs())
            {
                info!(
                    peer_zone = %hex::encode(zone),
                    block_id,
                    waited_secs = waited.as_secs(),
                    reason = if self.watch.is_suspended(zone) {
                        "reader suspended on the committee floor"
                    } else {
                        "reader is behind"
                    },
                    "Waiting for peer zone to finalize block"
                );
            }
            tokio::time::sleep(PEER_BLOCK_POLL_INTERVAL).await;
            waited = waited.saturating_add(PEER_BLOCK_POLL_INTERVAL);
        }
    }

    async fn refetch_evicted(
        &self,
        zone: ZoneId,
        block_id: u64,
        read_at: Slot,
        block_hash: HashType,
    ) -> anyhow::Result<Block> {
        self.refetch_attempts.fetch_add(1, Ordering::Relaxed);
        let indexer = self
            .refetch_clients
            .get(&zone)
            .ok_or_else(|| anyhow!("no channel client for peer zone {}", hex::encode(zone)))?;
        let cursor = read_at.into_inner().checked_sub(1).map(Slot::from);
        let stream = indexer
            .next_messages(cursor)
            .await
            .map_err(|err| anyhow!("channel read failed: {err}"))?;
        let stream = stop_at_read_error(
            stream,
            tracing::error_span!("peer_block_refetch", peer_zone = %hex::encode(zone), block_id),
        );
        refetched_block(stream, read_at, block_id, block_hash).await
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PeerPass {
    cursor: Option<Slot>,
    stalled_at: Option<Slot>,
}

fn absence_verdict(zone: ZoneId, block_id: u64, evidence: &AbsenceEvidence) -> String {
    format!(
        "peer zone {} holds no block {block_id}: its reader drained at channel tip slot {} on {} straight passes covering the full wait, the verified tip is {}, and the view's LIB slot {} covers the halting block's inscription",
        hex::encode(zone),
        evidence.channel_tip_slot,
        evidence.drained_passes,
        evidence
            .verified_tip
            .map_or_else(|| "absent".to_owned(), |tip| format!("block {tip}")),
        evidence.lib_slot,
    )
}

async fn channel_tip_reached(
    node: &TimeoutNode<NodeHttpClient>,
    peer_zone: ZoneId,
    cursor: Option<Slot>,
) -> Option<u64> {
    let state = node
        .channel_state(ChannelId::from(peer_zone))
        .await
        .ok()??;
    let tip_slot = state.tip_slot.into_inner();
    (cursor?.into_inner() >= tip_slot).then_some(tip_slot)
}

async fn peer_committee(
    node: &TimeoutNode<NodeHttpClient>,
    peer_zone: ZoneId,
) -> Option<(usize, u64)> {
    let state = node
        .channel_state(ChannelId::from(peer_zone))
        .await
        .ok()??;
    Some((state.accredited_keys.len(), state.tip_slot.into_inner()))
}

fn describe_committee(last_read: Option<(usize, u64)>) -> String {
    match last_read {
        Some((size, tip_slot)) => {
            format!("{size} accredited keys last seen at channel tip slot {tip_slot}")
        }
        None => "size unknown, channel state never read".to_owned(),
    }
}

async fn observed_lib_slot(node: &TimeoutNode<NodeHttpClient>) -> Option<u64> {
    let info = node.consensus_info().await.ok()?;
    Some(info.cryptarchia_info.lib_slot.into_inner())
}

const fn forged(msg: &CrossZoneMessage, verdict: String) -> CrossZoneVerifyError {
    CrossZoneVerifyError::Forged(ForgedDispatch {
        src_zone: msg.src_zone,
        src_block_id: msg.src_block_id,
        src_outbound_index: msg.src_outbound_index,
        verdict,
    })
}

fn seen_key(msg: &CrossZoneMessage) -> SeenKey {
    (
        message_key(&msg.src_zone, msg.src_block_id, msg.src_outbound_index),
        msg.src_block_hash,
    )
}

fn accept_peer_block(block: &Block) -> bool {
    match screen_peer_block(block) {
        Ok(_) => true,
        Err(refusal) => {
            warn!(reason = %refusal, "Peer reader dropping block");
            false
        }
    }
}

#[expect(
    clippy::infinite_loop,
    reason = "the peer reader runs for the lifetime of the indexer process"
)]
async fn read_peer(
    zone_indexer: ZoneIndexer<TimeoutNode<NodeHttpClient>>,
    tip_node: TimeoutNode<NodeHttpClient>,
    peer_zone: ZoneId,
    min_committee_size: u32,
    peers: PeerBlocks,
    watch: PeerWatch,
    poll_interval: Duration,
) {
    info!("Cross-zone peer reader started");

    let mut cursor = None;
    let mut stall = StallState::default();
    let mut floor = CommitteeFloorState::new(min_committee_size);
    loop {
        if floor.enforced() {
            match floor.after_read(peer_committee(&tip_node, peer_zone).await) {
                FloorVerdict::Suspended { passes, last_read } => {
                    watch.report_suspended(peer_zone);
                    if passes == 1 || alerts_at(passes) {
                        error!(
                            passes,
                            committee = %describe_committee(last_read),
                            min_committee_size,
                            "Peer reader suspended: peer committee below the floor. No new blocks \
                             from that peer are verified or cached until its committee recovers; \
                             dispatches naming unverified blocks wait rather than escalate."
                        );
                    }
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
                FloorVerdict::Active { resumed: true } => {
                    info!(
                        min_committee_size,
                        "Peer reader resumed: peer committee back at or above the floor"
                    );
                }
                FloorVerdict::Active { resumed: false } => {}
            }
        }
        match zone_indexer.next_messages(cursor).await {
            Ok(stream) => {
                let stream = stop_at_read_error(stream, tracing::Span::current());
                let pass = consume_peer_stream(stream, peer_zone, &peers, cursor).await;
                cursor = pass.cursor;
                if let Some((slot, attempts)) = stall.after_pass(pass.stalled_at, pass.cursor)
                    && alerts_at(attempts)
                {
                    error!(
                        slot = slot.into_inner(),
                        passes = attempts,
                        "Peer reader is stuck at a slot. The run verified from that peer's genesis \
                         stops below it, so every dispatch naming a later block stalls until this \
                         slot can be read."
                    );
                }
                let drained = pass.stalled_at.is_none();
                let drained_at_tip = if drained {
                    channel_tip_reached(&tip_node, peer_zone, pass.cursor).await
                } else {
                    None
                };
                let lib_slot = if drained_at_tip.is_some() {
                    observed_lib_slot(&tip_node).await
                } else {
                    None
                };
                watch.report_pass(
                    peer_zone,
                    &PassReport {
                        cursor_slot: pass.cursor.map(Slot::into_inner),
                        verified_tip: peers.verified_prefix(peer_zone).await,
                        stuck: stall
                            .current()
                            .map(|(slot, attempts)| (slot.into_inner(), attempts)),
                        drained,
                        drained_at_tip,
                        lib_slot,
                        pin_refused: peers.pin_refused(peer_zone).await,
                    },
                );
            }
            Err(err) => {
                error!(error = %err, "Peer reader next_messages failed");
                watch.report_failed_pass(peer_zone);
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn consume_peer_stream<S>(
    stream: S,
    peer_zone: ZoneId,
    peers: &PeerBlocks,
    resume_from: Option<Slot>,
) -> PeerPass
where
    S: Stream<Item = (ZoneMessage, Slot)>,
{
    let mut stream = std::pin::pin!(stream);
    let mut cursor = resume_from;
    let mut in_progress: Option<Slot> = None;

    while let Some((msg, slot)) = stream.next().await {
        if in_progress != Some(slot) {
            cursor = in_progress.or(cursor);
            in_progress = Some(slot);
        }

        let ZoneMessage::Block(zone_block) = msg else {
            continue;
        };
        match borsh::from_slice::<Block>(&zone_block.data) {
            Ok(block) => {
                if accept_peer_block(&block) {
                    peers.insert(peer_zone, block, slot).await;
                }
            }
            Err(err) => {
                error!(
                    slot = slot.into_inner(),
                    error = %err,
                    "Peer reader failed to deserialize block. Holding the cursor and retrying."
                );
                return PeerPass {
                    cursor,
                    stalled_at: Some(slot),
                };
            }
        }
    }

    PeerPass {
        cursor: in_progress.or(cursor),
        stalled_at: None,
    }
}

async fn refetched_block<S>(
    stream: S,
    read_at: Slot,
    block_id: u64,
    block_hash: HashType,
) -> anyhow::Result<Block>
where
    S: Stream<Item = (ZoneMessage, Slot)>,
{
    let mut stream = std::pin::pin!(stream);
    let mut mismatch = None;
    while let Some((msg, slot)) = stream.next().await {
        if slot > read_at {
            break;
        }
        if slot != read_at {
            continue;
        }
        let ZoneMessage::Block(zone_block) = msg else {
            continue;
        };
        let Ok(mut block) = borsh::from_slice::<Block>(&zone_block.data) else {
            continue;
        };
        if block.header.block_id != block_id {
            continue;
        }
        let recomputed = block.recompute_hash();
        if recomputed == block_hash {
            block.header.hash = recomputed;
            return Ok(block);
        }
        mismatch = Some(recomputed);
    }
    Err(mismatch.map_or_else(
        || anyhow!("slot {read_at:?} no longer serves peer block {block_id}"),
        |served| {
            anyhow!(
                "peer block {block_id} at slot {read_at:?} now hashes to {}, the verified walk recorded {}: the channel served different bytes than the walk saw",
                hex::encode(served.0),
                hex::encode(block_hash.0)
            )
        },
    ))
}

#[cfg(test)]
mod tests {
    use common::{
        HashType,
        test_utils::{produce_dummy_block, produce_dummy_block_with_outbound},
    };
    use cross_zone::test_utils::{linked_chain_with_outbound, ping_outbound};
    use futures::stream;
    use logos_blockchain_core::mantle::ops::channel::{MsgId, inscribe::Inscription};
    use logos_blockchain_zone_sdk::{UnverifiedEd25519PublicKey, ZoneBlock};

    use super::*;

    const SELF_ZONE: ZoneId = [1; 32];
    const PEER_ZONE: ZoneId = [2; 32];
    const PEER_BLOCK_ID: u64 = 5;
    const _: () = assert!(PEER_BLOCK_ID >= GENESIS_BLOCK_ID);
    const READ_SLOT: Slot = Slot::new(0);
    fn verifier() -> CrossZoneVerifier {
        CrossZoneVerifier {
            self_zone: SELF_ZONE,
            peers: PeerBlocks::default(),
            refetch_clients: HashMap::new(),
            refetch_attempts: Arc::new(AtomicU64::new(0)),
            seen: Arc::new(RwLock::new(HashSet::new())),
            watch: PeerWatch::default(),
        }
    }

    fn window(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).expect("test windows are nonzero")
    }

    fn verifier_with_window(n: u32) -> CrossZoneVerifier {
        CrossZoneVerifier {
            peers: PeerBlocks::new(window(n)),
            ..verifier()
        }
    }

    async fn cache_chain_with_slots(peers: &PeerBlocks, chain: Vec<Block>) {
        for block in chain {
            let read_at = Slot::from(block.header.block_id);
            peers.insert(PEER_ZONE, block, read_at).await;
        }
    }

    fn outbound(payload: &[u8]) -> lee::OutboundMessage {
        ping_outbound(SELF_ZONE, payload)
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

    fn linked_chain(len: u64) -> Vec<Block> {
        linked_chain_with_outbound(
            GENESIS_BLOCK_ID.saturating_add(len).saturating_sub(1),
            |_| vec![outbound(b"hi")],
        )
    }

    fn peer_block_msg(block: &Block, slot: u64) -> (ZoneMessage, Slot) {
        peer_msg(borsh::to_vec(block).expect("block serializes"), slot)
    }

    fn peer_chain(payload: &[u8]) -> Vec<Block> {
        linked_chain_with_outbound(PEER_BLOCK_ID, |block_id| {
            vec![if block_id == PEER_BLOCK_ID {
                outbound(payload)
            } else {
                outbound(b"hi")
            }]
        })
    }

    async fn cache_chain(verifier: &CrossZoneVerifier, chain: Vec<Block>) {
        for block in chain {
            verifier.peers.insert(PEER_ZONE, block, READ_SLOT).await;
        }
    }

    fn undecodable_msg(slot: u64) -> (ZoneMessage, Slot) {
        peer_msg(b"not a block".to_vec(), slot)
    }

    fn dispatch(payload: &[u8]) -> LeeTransaction {
        dispatch_naming_block_hash(payload, source_block_hash(payload))
    }

    fn source_block_hash(payload: &[u8]) -> [u8; 32] {
        peer_chain(payload)
            .last()
            .expect("chain reaches PEER_BLOCK_ID")
            .recompute_hash()
            .0
    }

    fn dispatch_naming_block_hash(payload: &[u8], src_block_hash: [u8; 32]) -> LeeTransaction {
        LeeTransaction::Public(build_dispatch(
            &OutboundSource {
                src_zone: PEER_ZONE,
                src_block_id: PEER_BLOCK_ID,
                src_block_hash,
                src_outbound_index: 0,
            },
            &outbound(payload),
        ))
    }

    #[tokio::test]
    async fn verifies_dispatch_matching_a_peer_emission() {
        let verifier = verifier();
        cache_chain(&verifier, peer_chain(b"hi")).await;

        let block = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        verifier
            .verify_block(&block, Slot::from(0))
            .await
            .expect("dispatch matching the peer emission verifies");
    }

    #[tokio::test]
    async fn rejects_dispatch_naming_the_wrong_source_block_hash() {
        let verifier = verifier();
        cache_chain(&verifier, peer_chain(b"hi")).await;

        let block =
            produce_dummy_block(9, None, vec![dispatch_naming_block_hash(b"hi", [0xab; 32])]);
        assert!(
            matches!(
                verifier.verify_block(&block, Slot::from(0)).await,
                Err(CrossZoneVerifyError::Forged(_))
            ),
            "a delivery claiming a source block hash the peer block does not have is forged"
        );
    }

    #[tokio::test]
    async fn rejects_dispatch_with_no_matching_emission() {
        let verifier = verifier();
        cache_chain(&verifier, peer_chain(b"real")).await;

        let block = produce_dummy_block(9, None, vec![dispatch(b"forged")]);
        let err = verifier
            .verify_block(&block, Slot::from(0))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("forged"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn leaves_a_replayed_dispatch_to_the_inbox() {
        let verifier = verifier();
        cache_chain(&verifier, peer_chain(b"hi")).await;

        let first = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        let keys = verifier
            .verify_block(&first, Slot::from(0))
            .await
            .expect("first delivery verifies");
        verifier.record_seen(keys).await;

        let replay = produce_dummy_block(
            10,
            None,
            vec![dispatch_naming_block_hash(
                b"forged",
                source_block_hash(b"hi"),
            )],
        );
        verifier
            .verify_block(&replay, Slot::from(0))
            .await
            .expect("a replay is left to the inbox, which refuses it on chain");
    }

    #[tokio::test]
    async fn a_seen_coordinate_does_not_excuse_a_different_source_block() {
        let verifier = verifier();
        cache_chain(&verifier, peer_chain(b"hi")).await;

        let first = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        let keys = verifier
            .verify_block(&first, Slot::from(0))
            .await
            .expect("first verifies");
        verifier.record_seen(keys).await;

        let other = produce_dummy_block(
            10,
            None,
            vec![dispatch_naming_block_hash(b"hi", [0xab; 32])],
        );
        assert!(
            matches!(
                verifier.verify_block(&other, Slot::from(0)).await,
                Err(CrossZoneVerifyError::Forged(_))
            ),
            "the seen set must agree with the guest on what counts as a replay"
        );
    }

    #[tokio::test]
    async fn unaccepted_dispatch_does_not_poison_seen() {
        let verifier = verifier();
        cache_chain(&verifier, peer_chain(b"hi")).await;

        let first = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        verifier
            .verify_block(&first, Slot::from(0))
            .await
            .expect("dispatch verifies");

        let forged = produce_dummy_block(10, None, vec![dispatch(b"forged")]);
        let err = verifier
            .verify_block(&forged, Slot::from(0))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("forged"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn peer_reader_advances_over_a_fully_decoded_stream() {
        let peers = PeerBlocks::default();
        let chain = linked_chain(2);
        let stream = stream::iter(vec![
            peer_block_msg(&chain[0], 0),
            peer_block_msg(&chain[1], 1),
        ]);

        let pass = consume_peer_stream(stream, PEER_ZONE, &peers, None).await;

        assert_eq!(pass.cursor, Some(Slot::from(1)));
        assert_eq!(pass.stalled_at, None);
        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(2));
    }

    #[tokio::test]
    async fn a_block_that_does_not_link_does_not_extend_the_verified_run() {
        let peers = PeerBlocks::default();
        let genesis = linked_chain(1);
        peers.insert(PEER_ZONE, genesis[0].clone(), READ_SLOT).await;
        peers
            .insert(
                PEER_ZONE,
                produce_dummy_block_with_outbound(
                    GENESIS_BLOCK_ID + 1,
                    None,
                    vec![outbound(b"hi")],
                ),
                READ_SLOT,
            )
            .await;

        assert_eq!(
            peers.verified_prefix(PEER_ZONE).await,
            Some(GENESIS_BLOCK_ID)
        );
    }

    #[tokio::test]
    async fn a_block_arriving_between_the_two_halves_of_a_lookup_is_not_forged() {
        let peers = PeerBlocks::default();
        for block in linked_chain(2) {
            peers.insert(PEER_ZONE, block, READ_SLOT).await;
        }

        assert!(matches!(
            peers.resolve(PEER_ZONE, 2).await,
            PeerLookup::Cached(_)
        ));
        assert!(matches!(
            peers.resolve(PEER_ZONE, 3).await,
            PeerLookup::Behind
        ));
    }

    #[tokio::test]
    async fn the_tip_survives_the_tip_block_leaving_the_cache() {
        let peers = PeerBlocks::default();
        let chain = linked_chain(3);
        for block in chain.iter().take(2).cloned() {
            peers.insert(PEER_ZONE, block, READ_SLOT).await;
        }
        peers
            .chains
            .write()
            .await
            .get_mut(&PEER_ZONE)
            .expect("chain exists")
            .blocks
            .remove(&2);

        assert!(
            peers.insert(PEER_ZONE, chain[2].clone(), READ_SLOT).await,
            "the next block still extends the run off the pinned tip"
        );
        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(3));
        assert!(matches!(
            peers.resolve(PEER_ZONE, 2).await,
            PeerLookup::InsideRun
        ));
        assert!(matches!(
            peers.resolve(PEER_ZONE, 4).await,
            PeerLookup::Behind
        ));
    }

    #[tokio::test]
    async fn peer_reader_holds_its_cursor_on_an_undecodable_block() {
        let peers = PeerBlocks::default();
        let chain = linked_chain(3);
        let stream = stream::iter(vec![
            peer_block_msg(&chain[0], 0),
            undecodable_msg(1),
            peer_block_msg(&chain[2], 2),
        ]);

        let pass = consume_peer_stream(stream, PEER_ZONE, &peers, None).await;

        assert_eq!(pass.cursor, Some(Slot::from(0)));
        assert_eq!(pass.stalled_at, Some(Slot::from(1)));
        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(1));
        assert!(peers.get(PEER_ZONE, 3).await.is_none());
    }

    #[tokio::test]
    async fn peer_reader_does_not_resume_inside_a_partially_failed_slot() {
        let peers = PeerBlocks::default();
        let chain = linked_chain(1);
        let stream = stream::iter(vec![peer_block_msg(&chain[0], 7), undecodable_msg(7)]);

        let pass = consume_peer_stream(stream, PEER_ZONE, &peers, Some(Slot::from(6))).await;

        assert_eq!(pass.cursor, Some(Slot::from(6)));
    }

    #[tokio::test]
    async fn peer_reader_never_reads_past_a_slot_it_cannot_decode() {
        let peers = PeerBlocks::default();
        let chain = linked_chain(3);
        let stream = stream::iter(vec![
            peer_block_msg(&chain[0], 0),
            undecodable_msg(1),
            peer_block_msg(&chain[2], 2),
        ]);

        let pass = consume_peer_stream(stream, PEER_ZONE, &peers, None).await;

        assert_eq!(pass.cursor, Some(Slot::from(0)), "the slot is held");
        assert_eq!(pass.stalled_at, Some(Slot::from(1)));
        assert!(
            peers.get(PEER_ZONE, 3).await.is_none(),
            "nothing past the hole is even read"
        );
        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(1));
    }

    #[tokio::test(start_paused = true)]
    async fn undecodable_peer_block_does_not_make_a_later_dispatch_look_forged() {
        let verifier = verifier();
        let chain = linked_chain(3);
        let stream = stream::iter(vec![
            peer_block_msg(&chain[0], 0),
            undecodable_msg(1),
            peer_block_msg(&chain[2], 2),
        ]);
        consume_peer_stream(stream, PEER_ZONE, &verifier.peers, None).await;

        let err = verifier
            .wait_for_peer_block(PEER_ZONE, 2, 0)
            .await
            .expect_err("block 2 was never read, so it cannot be resolved");
        assert!(
            matches!(err, PeerBlockError::Unavailable { .. }),
            "a block outside the verified run is lag, not forgery: {err:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_block_ahead_of_the_run_is_not_cached_and_not_delivered_from() {
        let verifier = verifier();
        cache_chain(&verifier, linked_chain(2)).await;
        let claimed = produce_dummy_block_with_outbound(9, None, vec![outbound(b"hi")]);
        assert!(
            !verifier.peers.insert(PEER_ZONE, claimed, READ_SLOT).await,
            "the reader takes the next block on the run, never one ahead of it"
        );
        assert!(verifier.peers.get(PEER_ZONE, 9).await.is_none());

        let err = verifier
            .wait_for_peer_block(PEER_ZONE, 9, 0)
            .await
            .expect_err("a block off the verified run must not resolve");
        assert!(
            matches!(err, PeerBlockError::Unavailable { .. }),
            "a claimed id and a reader that is behind read alike, so this stalls rather than halting: {err:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_high_block_id_cannot_poison_the_forgery_test() {
        let verifier = verifier();
        let chain = linked_chain(2);
        verifier
            .peers
            .insert(PEER_ZONE, chain[0].clone(), READ_SLOT)
            .await;
        verifier
            .peers
            .insert(PEER_ZONE, chain[1].clone(), READ_SLOT)
            .await;
        verifier
            .peers
            .insert(
                PEER_ZONE,
                produce_dummy_block_with_outbound(u64::MAX, None, vec![outbound(b"hi")]),
                READ_SLOT,
            )
            .await;

        assert_eq!(verifier.peers.verified_prefix(PEER_ZONE).await, Some(2));
        let err = verifier
            .wait_for_peer_block(PEER_ZONE, 3, 0)
            .await
            .expect_err("block 3 has not been read yet");
        assert!(
            matches!(err, PeerBlockError::Unavailable { .. }),
            "a block beyond the verified run is lag, not forgery: {err:?}"
        );
    }

    #[tokio::test]
    async fn a_transient_decode_failure_heals_on_the_next_pass() {
        let verifier = verifier();
        let chain = linked_chain(PEER_BLOCK_ID);

        let pass = consume_peer_stream(
            stream::iter(vec![undecodable_msg(0)]),
            PEER_ZONE,
            &verifier.peers,
            None,
        )
        .await;
        assert_eq!(pass.cursor, None, "the failed slot is not skipped");
        assert_eq!(pass.stalled_at, Some(Slot::from(0)));

        let pass = consume_peer_stream(
            stream::iter(chain.iter().enumerate().map(|(index, block)| {
                peer_block_msg(block, u64::try_from(index).expect("test index fits in u64"))
            })),
            PEER_ZONE,
            &verifier.peers,
            pass.cursor,
        )
        .await;
        assert_eq!(pass.stalled_at, None);

        let block = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        verifier
            .verify_block(&block, Slot::from(0))
            .await
            .expect("the dispatch verifies once the peer block has been read");
    }

    #[tokio::test]
    async fn an_equivocating_peer_cannot_replace_a_cached_block() {
        let verifier = verifier();
        let mut chain = peer_chain(b"hi");
        let real = chain.pop().expect("chain has a last block");
        let impostor = produce_dummy_block_with_outbound(
            PEER_BLOCK_ID,
            Some(real.header.prev_block_hash),
            vec![outbound(b"forged")],
        );
        assert_ne!(
            real.header.hash, impostor.header.hash,
            "the two blocks must differ, or this proves nothing"
        );

        cache_chain(&verifier, chain).await;
        assert!(
            verifier
                .peers
                .insert(PEER_ZONE, real.clone(), READ_SLOT)
                .await
        );
        assert!(
            !verifier.peers.insert(PEER_ZONE, impostor, READ_SLOT).await,
            "a differing block at a held id must be refused"
        );
        assert_eq!(
            verifier
                .peers
                .get(PEER_ZONE, PEER_BLOCK_ID)
                .await
                .unwrap()
                .header
                .hash,
            real.header.hash,
            "the block held first stays"
        );

        let block = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        verifier
            .verify_block(&block, Slot::from(0))
            .await
            .expect("equivocation must not halt ingestion of an honest dispatch");
    }

    #[tokio::test]
    async fn a_non_linking_block_at_the_run_head_does_not_lock_that_id_out() {
        let peers = PeerBlocks::default();
        let chain = linked_chain(3);
        for block in chain.iter().take(2).cloned() {
            peers.insert(PEER_ZONE, block, READ_SLOT).await;
        }
        let claimed = produce_dummy_block_with_outbound(
            3,
            Some(HashType([9; 32])),
            vec![outbound(b"claimed")],
        );
        assert!(peers.insert(PEER_ZONE, claimed, READ_SLOT).await);
        assert_eq!(
            peers.verified_prefix(PEER_ZONE).await,
            Some(2),
            "it cannot extend the run, which is what makes it inert but sticky"
        );

        let honest = chain[2].clone();
        assert!(
            peers.insert(PEER_ZONE, honest.clone(), READ_SLOT).await,
            "the block that continues the run displaces the one that never could"
        );
        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(3));
        assert_eq!(
            peers.get(PEER_ZONE, 3).await.unwrap().header.hash,
            honest.header.hash
        );
    }

    #[tokio::test]
    async fn a_block_ahead_of_the_run_cannot_win_an_id_the_watcher_gave_to_another() {
        let peers = PeerBlocks::default();
        let chain = linked_chain(4);
        for block in chain.iter().take(2).cloned() {
            peers.insert(PEER_ZONE, block, READ_SLOT).await;
        }
        let ahead = produce_dummy_block_with_outbound(
            4,
            Some(chain[2].header.hash),
            vec![outbound(b"ahead")],
        );
        assert!(!peers.insert(PEER_ZONE, ahead, READ_SLOT).await);

        peers.insert(PEER_ZONE, chain[2].clone(), READ_SLOT).await;
        peers.insert(PEER_ZONE, chain[3].clone(), READ_SLOT).await;

        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(4));
        assert_eq!(
            peers.get(PEER_ZONE, 4).await.unwrap().header.hash,
            chain[3].header.hash,
            "the run holds the block the watcher delivered from"
        );
    }

    #[tokio::test]
    async fn a_block_below_the_peers_genesis_is_not_cached() {
        let peers = PeerBlocks::default();
        let below = produce_dummy_block_with_outbound(0, None, vec![outbound(b"below")]);
        assert!(!peers.insert(PEER_ZONE, below, READ_SLOT).await);

        for block in linked_chain(3) {
            peers.insert(PEER_ZONE, block, READ_SLOT).await;
        }
        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(3));
        assert!(peers.get(PEER_ZONE, 0).await.is_none());
        assert!(matches!(
            peers.resolve(PEER_ZONE, 0).await,
            PeerLookup::InsideRun
        ));
    }

    #[tokio::test]
    async fn a_peer_whose_genesis_is_unread_resolves_to_behind() {
        let peers = PeerBlocks::default();
        assert_eq!(peers.verified_prefix(PEER_ZONE).await, None);
        assert!(matches!(
            peers.resolve(PEER_ZONE, GENESIS_BLOCK_ID).await,
            PeerLookup::Behind
        ));
        assert!(matches!(
            peers.resolve(PEER_ZONE, 9).await,
            PeerLookup::Behind
        ));
    }

    #[tokio::test]
    async fn a_block_inside_the_verified_run_is_never_displaced() {
        let peers = PeerBlocks::default();
        let chain = linked_chain(2);
        for block in chain.iter().cloned() {
            peers.insert(PEER_ZONE, block, READ_SLOT).await;
        }
        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(2));

        let impostor = produce_dummy_block_with_outbound(
            2,
            Some(chain[0].header.hash),
            vec![outbound(b"forged")],
        );
        assert!(
            !peers.insert(PEER_ZONE, impostor, READ_SLOT).await,
            "it links to block 1 just as the held block does, and the run has certified the held one"
        );

        let plausible = produce_dummy_block_with_outbound(
            2,
            Some(chain[1].header.hash),
            vec![outbound(b"forged")],
        );
        assert!(
            !peers.insert(PEER_ZONE, plausible, READ_SLOT).await,
            "displacement fires only at the id that would extend the run, never inside it"
        );
        assert_eq!(
            peers.get(PEER_ZONE, 2).await.unwrap().header.hash,
            chain[1].header.hash
        );
    }

    #[tokio::test]
    async fn re_reading_the_same_block_is_not_equivocation() {
        let verifier = verifier();
        let block = linked_chain(1).pop().expect("genesis block");

        assert!(
            verifier
                .peers
                .insert(PEER_ZONE, block.clone(), READ_SLOT)
                .await
        );
        assert!(
            !verifier
                .peers
                .insert(PEER_ZONE, block.clone(), READ_SLOT)
                .await,
            "an identical re-read is already held, not newly cached"
        );
        assert_eq!(
            verifier
                .peers
                .get(PEER_ZONE, GENESIS_BLOCK_ID)
                .await
                .unwrap()
                .header
                .hash,
            block.header.hash
        );
    }

    #[tokio::test]
    async fn a_block_whose_hash_does_not_match_its_contents_is_not_cached() {
        let verifier = verifier();
        let mut tampered =
            produce_dummy_block_with_outbound(PEER_BLOCK_ID, None, vec![outbound(b"hi")]);
        tampered.header.hash = common::HashType([0xAB; 32]);

        let pass = consume_peer_stream(
            stream::iter(vec![peer_block_msg(&tampered, 0)]),
            PEER_ZONE,
            &verifier.peers,
            None,
        )
        .await;

        assert_eq!(
            pass.stalled_at, None,
            "a rejected block is not a decode failure"
        );
        assert!(
            verifier.peers.get(PEER_ZONE, PEER_BLOCK_ID).await.is_none(),
            "a block that does not hash to its own contents must not be cached"
        );
    }

    fn at_tip_report(verified_tip: u64, tip_slot: u64) -> PassReport {
        at_tip_report_with_lib(verified_tip, tip_slot, Some(tip_slot))
    }

    fn at_tip_report_with_lib(
        verified_tip: u64,
        tip_slot: u64,
        lib_slot: Option<u64>,
    ) -> PassReport {
        PassReport {
            cursor_slot: Some(tip_slot),
            verified_tip: Some(verified_tip),
            stuck: None,
            drained: true,
            drained_at_tip: Some(tip_slot),
            lib_slot,
            pin_refused: false,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn at_tip_passes_accumulate_and_any_break_resets_the_run() {
        let watch = PeerWatch::default();
        let start = Instant::now();
        watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
        watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
        let evidence = watch
            .confirmed_absence(PEER_ZONE, start, 0)
            .expect("an intact at-tip run is evidence");
        assert_eq!(evidence.drained_passes, 2);
        assert_eq!(evidence.channel_tip_slot, 7);
        assert_eq!(evidence.verified_tip, Some(2));
        assert_eq!(evidence.lib_slot, 7);

        watch.report_failed_pass(PEER_ZONE);
        assert!(
            watch.confirmed_absence(PEER_ZONE, start, 0).is_none(),
            "a failed pass clears the run"
        );

        tokio::time::sleep(Duration::from_secs(1)).await;
        watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
        assert!(
            watch.confirmed_absence(PEER_ZONE, start, 0).is_none(),
            "the new run started after the wait, so it does not cover it"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn suspension_clears_the_evidence_run_and_it_rebuilds_from_scratch() {
        let watch = PeerWatch::default();
        let start = Instant::now();
        watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
        watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
        assert!(watch.confirmed_absence(PEER_ZONE, start, 0).is_some());

        watch.report_suspended(PEER_ZONE);
        assert!(
            watch.confirmed_absence(PEER_ZONE, start, 0).is_none(),
            "a suspension clears the run"
        );

        watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
        let evidence = watch
            .confirmed_absence(PEER_ZONE, start, 0)
            .expect("a fresh at-tip run is evidence again");
        assert_eq!(
            evidence.drained_passes, 1,
            "the run restarts from scratch after a suspension"
        );
    }

    #[tokio::test]
    async fn a_pinned_genesis_refusal_latches_until_the_pinned_chain_anchors() {
        let honest = linked_chain_with_outbound(GENESIS_BLOCK_ID, |_| vec![]);
        let pinned = honest[0].header.hash;
        let peers =
            PeerBlocks::new(window(1)).with_genesis_pins(HashMap::from([(PEER_ZONE, pinned)]));

        let fabricated = produce_dummy_block(GENESIS_BLOCK_ID, Some(HashType([7; 32])), vec![]);
        assert!(!peers.insert(PEER_ZONE, fabricated, READ_SLOT).await);
        assert!(peers.pin_refused(PEER_ZONE).await);

        assert!(peers.insert(PEER_ZONE, honest[0].clone(), READ_SLOT).await);
        assert!(
            !peers.pin_refused(PEER_ZONE).await,
            "the pinned genesis anchoring clears the refusal"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_pin_refusal_blocks_absence_evidence_and_surfaces_in_health() {
        let watch = PeerWatch::default();
        let start = Instant::now();
        let refused = PassReport {
            verified_tip: None,
            pin_refused: true,
            ..at_tip_report(2, 7)
        };
        watch.report_pass(PEER_ZONE, &refused);
        watch.report_pass(PEER_ZONE, &refused);
        assert!(
            watch.confirmed_absence(PEER_ZONE, start, 0).is_none(),
            "a reader draining a chain it refuses to verify proves no absence"
        );
        assert_eq!(watch.statuses()[0].health, PeerHealth::PinMismatch);

        watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
        let evidence = watch
            .confirmed_absence(PEER_ZONE, start, 0)
            .expect("a fresh at-tip run is evidence again");
        assert_eq!(
            evidence.drained_passes, 1,
            "the run restarts from scratch after the pin anchors"
        );
        assert_eq!(watch.statuses()[0].health, PeerHealth::Live);
    }

    #[test]
    fn suspension_precedence_and_recovery() {
        let watch = PeerWatch::default();

        watch.report_suspended(PEER_ZONE);
        watch.mark_halted(PEER_ZONE);
        assert_eq!(watch.statuses()[0].health, PeerHealth::Halted);
        watch.clear_halted(PEER_ZONE);

        watch.report_pass(
            PEER_ZONE,
            &PassReport {
                cursor_slot: Some(3),
                verified_tip: Some(1),
                stuck: Some((4, 3)),
                drained: false,
                drained_at_tip: None,
                lib_slot: None,
                pin_refused: false,
            },
        );
        watch.report_suspended(PEER_ZONE);
        assert_eq!(
            watch.statuses()[0].health,
            PeerHealth::Suspended,
            "a stall observed before the dip is stale information"
        );

        watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
        assert_eq!(
            watch.statuses()[0].health,
            PeerHealth::Live,
            "one ordinary pass clears the suspension"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_lagging_or_stalled_pass_resets_the_run() {
        let watch = PeerWatch::default();
        let start = Instant::now();

        watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
        watch.report_pass(
            PEER_ZONE,
            &PassReport {
                cursor_slot: Some(5),
                verified_tip: Some(2),
                stuck: None,
                drained: true,
                drained_at_tip: None,
                lib_slot: None,
                pin_refused: false,
            },
        );
        assert!(watch.confirmed_absence(PEER_ZONE, start, 0).is_none());

        watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
        watch.report_pass(
            PEER_ZONE,
            &PassReport {
                cursor_slot: Some(6),
                verified_tip: Some(2),
                stuck: Some((7, 1)),
                drained: false,
                drained_at_tip: None,
                lib_slot: None,
                pin_refused: false,
            },
        );
        assert!(watch.confirmed_absence(PEER_ZONE, start, 0).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn an_id_beyond_a_provably_drained_peer_channel_escalates_to_forged() {
        let verifier = verifier();
        cache_chain(&verifier, linked_chain(2)).await;
        verifier.watch.register(PEER_ZONE);
        verifier.watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));

        let wait = verifier.wait_for_peer_block(PEER_ZONE, 9, 7);
        let keep_reporting = async {
            for _ in 0_u32..40 {
                tokio::time::sleep(Duration::from_secs(10)).await;
                verifier.watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
            }
        };
        let (result, ()) = tokio::join!(wait, keep_reporting);
        let err = result.expect_err("the id cannot exist on the drained channel");
        let PeerBlockError::NotOnPeerChain(verdict) = err else {
            panic!("expected a permanent verdict, got {err:?}");
        };
        assert!(verdict.contains("no block 9"), "names the claim: {verdict}");
        assert!(
            verdict.contains("tip slot 7"),
            "names the channel tip: {verdict}"
        );
        assert!(
            verdict.contains("verified tip is block 2"),
            "names the verified tip: {verdict}"
        );
        assert!(
            verdict.contains("LIB slot 7"),
            "names the view's freshness: {verdict}"
        );

        let statuses = verifier.peer_statuses();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].health, PeerHealth::Halted);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stale_replica_view_cannot_refute_a_dispatch() {
        let verifier = verifier();
        cache_chain(&verifier, linked_chain(2)).await;
        verifier.watch.register(PEER_ZONE);
        verifier
            .watch
            .report_pass(PEER_ZONE, &at_tip_report_with_lib(2, 7, Some(7)));

        let wait = verifier.wait_for_peer_block(PEER_ZONE, 9, 8);
        let keep_reporting = async {
            for _ in 0_u32..40 {
                tokio::time::sleep(Duration::from_secs(10)).await;
                verifier
                    .watch
                    .report_pass(PEER_ZONE, &at_tip_report_with_lib(2, 7, Some(7)));
            }
        };
        let (result, ()) = tokio::join!(wait, keep_reporting);
        assert!(
            matches!(
                result.expect_err("still unresolved"),
                PeerBlockError::Unavailable { .. }
            ),
            "a view staler than the halting block's inscription must stall, not halt"
        );
        assert_ne!(
            verifier.peer_statuses()[0].health,
            PeerHealth::Halted,
            "no verdict was issued, so the peer is not marked halted"
        );
    }

    #[tokio::test]
    async fn a_successful_rederive_unsticks_the_halted_mark() {
        let verifier = verifier();
        cache_chain(&verifier, peer_chain(b"hi")).await;
        verifier.watch.register(PEER_ZONE);
        verifier.watch.mark_halted(PEER_ZONE);

        let block = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        verifier
            .verify_block(&block, Slot::from(0))
            .await
            .expect("the dispatch verifies");
        assert_ne!(
            verifier.peer_statuses()[0].health,
            PeerHealth::Halted,
            "the peer chain served the rederivation, so the mark no longer holds"
        );
    }

    #[tokio::test]
    async fn advancing_the_prefix_evicts_bodies_deeper_than_the_window() {
        let peers = PeerBlocks::new(window(1));
        let chain = linked_chain(4);
        cache_chain_with_slots(&peers, chain.clone()).await;

        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(4));
        let PeerLookup::Evicted {
            read_at,
            block_hash,
        } = peers.resolve(PEER_ZONE, 1).await
        else {
            panic!("id 1 must resolve as evicted");
        };
        assert_eq!(read_at, Slot::from(1), "the slot the reader recorded");
        assert_eq!(block_hash, chain[0].header.hash);
        assert!(matches!(
            peers.resolve(PEER_ZONE, 2).await,
            PeerLookup::Evicted { .. }
        ));
        assert!(matches!(
            peers.resolve(PEER_ZONE, 3).await,
            PeerLookup::Cached(_)
        ));
        assert!(matches!(
            peers.resolve(PEER_ZONE, 4).await,
            PeerLookup::Cached(_)
        ));
        assert!(peers.get(PEER_ZONE, 1).await.is_none(), "the body is gone");
        assert!(matches!(
            peers.resolve(PEER_ZONE, 0).await,
            PeerLookup::InsideRun
        ));
    }

    #[tokio::test]
    async fn exactly_window_bodies_stay_behind_the_tip() {
        let peers = PeerBlocks::new(window(2));
        cache_chain_with_slots(&peers, linked_chain(5)).await;

        assert!(matches!(
            peers.resolve(PEER_ZONE, 2).await,
            PeerLookup::Evicted { .. }
        ));
        assert!(matches!(
            peers.resolve(PEER_ZONE, 3).await,
            PeerLookup::Cached(_)
        ));
        assert!(matches!(
            peers.resolve(PEER_ZONE, 4).await,
            PeerLookup::Cached(_)
        ));
        assert!(matches!(
            peers.resolve(PEER_ZONE, 5).await,
            PeerLookup::Cached(_)
        ));
    }

    #[tokio::test]
    async fn a_u32_max_window_never_evicts() {
        let peers = PeerBlocks::new(window(u32::MAX));
        cache_chain_with_slots(&peers, linked_chain(6)).await;

        for block_id in GENESIS_BLOCK_ID..=6 {
            assert!(
                matches!(
                    peers.resolve(PEER_ZONE, block_id).await,
                    PeerLookup::Cached(_)
                ),
                "block {block_id} must keep its body under an effectively unbounded window"
            );
        }
    }

    #[test]
    fn a_zero_window_is_rejected_at_config_parse() {
        assert!(
            serde_json::from_str::<NonZeroU32>("0").is_err(),
            "zero must not deserialize into the window type"
        );
        assert_eq!(
            crate::config::default_peer_block_cache_window(),
            window(1024)
        );
    }

    #[tokio::test]
    async fn eviction_leaves_the_run_and_its_admission_rules_intact() {
        let peers = PeerBlocks::new(window(1));
        let chain = linked_chain(4);
        cache_chain_with_slots(&peers, chain.iter().take(3).cloned().collect()).await;
        assert!(matches!(
            peers.resolve(PEER_ZONE, 1).await,
            PeerLookup::Evicted { .. }
        ));

        assert!(peers.insert(PEER_ZONE, chain[3].clone(), READ_SLOT).await);
        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(4));

        let impostor = produce_dummy_block_with_outbound(1, None, vec![outbound(b"forged")]);
        assert!(!peers.insert(PEER_ZONE, impostor, READ_SLOT).await);
        let PeerLookup::Evicted { block_hash, .. } = peers.resolve(PEER_ZONE, 1).await else {
            panic!("the evicted entry must survive the equivocation attempt");
        };
        assert_eq!(block_hash, chain[0].header.hash);
    }

    #[tokio::test]
    async fn refetch_returns_the_block_the_walk_certified() {
        let chain = linked_chain(2);
        let target = &chain[1];
        let stream = stream::iter(vec![
            peer_block_msg(&chain[0], 3),
            peer_block_msg(target, 4),
        ]);

        let block = refetched_block(stream, Slot::from(4), 2, target.header.hash)
            .await
            .expect("the recorded slot serves the block");
        assert_eq!(block.header.hash, target.header.hash);
    }

    #[tokio::test]
    async fn refetch_recomputes_the_hash_rather_than_trusting_the_header() {
        let mut tampered = linked_chain(1).pop().expect("genesis block");
        let certified = tampered.recompute_hash();
        tampered.header.hash = HashType([0xAB; 32]);
        let stream = stream::iter(vec![peer_block_msg(&tampered, 4)]);

        let block = refetched_block(stream, Slot::from(4), GENESIS_BLOCK_ID, certified)
            .await
            .expect("the recomputed hash matches the index");
        assert_eq!(
            block.header.hash, certified,
            "the claimed hash is replaced with the recomputed one"
        );
    }

    #[tokio::test]
    async fn accept_list_acceptance_unsticks_the_halted_mark() {
        let verifier = verifier();
        verifier.watch.register(PEER_ZONE);
        verifier.watch.mark_halted(PEER_ZONE);

        let block = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        assert_eq!(
            verifier.accept_unverified(&block),
            CrossZoneVerifier::unverified_dispatch_keys(&block),
        );
        assert_ne!(verifier.peer_statuses()[0].health, PeerHealth::Halted);
    }

    #[tokio::test(start_paused = true)]
    async fn a_break_mid_wait_keeps_the_escalation_conservative() {
        let verifier = verifier();
        cache_chain(&verifier, linked_chain(2)).await;
        verifier.watch.register(PEER_ZONE);
        verifier.watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));

        let wait = verifier.wait_for_peer_block(PEER_ZONE, 9, 0);
        let reports = async {
            tokio::time::sleep(Duration::from_secs(50)).await;
            verifier.watch.report_pass(
                PEER_ZONE,
                &PassReport {
                    cursor_slot: Some(6),
                    verified_tip: Some(2),
                    stuck: Some((7, 1)),
                    drained: false,
                    drained_at_tip: None,
                    lib_slot: None,
                    pin_refused: false,
                },
            );
            for _ in 0_u32..40 {
                tokio::time::sleep(Duration::from_secs(10)).await;
                verifier.watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
            }
        };
        let (result, ()) = tokio::join!(wait, reports);
        assert!(
            matches!(
                result.expect_err("still unresolved"),
                PeerBlockError::Unavailable { .. }
            ),
            "a broken evidence run must stall, not halt"
        );
    }

    #[tokio::test]
    async fn a_suspended_peer_still_serves_previously_verified_blocks() {
        let verifier = verifier();
        cache_chain(&verifier, linked_chain(2)).await;
        verifier.watch.register(PEER_ZONE);
        verifier.watch.report_suspended(PEER_ZONE);

        verifier
            .wait_for_peer_block(PEER_ZONE, 2, 0)
            .await
            .expect("a block verified before the dip still serves");
    }

    #[tokio::test(start_paused = true)]
    async fn suspension_mid_wait_stays_unavailable_at_timeout() {
        let verifier = verifier();
        cache_chain(&verifier, linked_chain(2)).await;
        verifier.watch.register(PEER_ZONE);
        verifier.watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));

        let wait = verifier.wait_for_peer_block(PEER_ZONE, 9, 0);
        let reports = async {
            tokio::time::sleep(Duration::from_secs(50)).await;
            verifier.watch.report_suspended(PEER_ZONE);
            for _ in 0_u32..40 {
                tokio::time::sleep(Duration::from_secs(10)).await;
                verifier.watch.report_suspended(PEER_ZONE);
            }
        };
        let (result, ()) = tokio::join!(wait, reports);
        assert!(
            matches!(
                result.expect_err("still unresolved"),
                PeerBlockError::Unavailable { .. }
            ),
            "a suspended peer must stall the wait, not halt the zone"
        );
        assert_eq!(verifier.watch.statuses()[0].health, PeerHealth::Suspended);
    }

    #[tokio::test]
    async fn refetch_refuses_a_block_hashing_differently_than_the_index() {
        let chain = linked_chain(2);
        let served = produce_dummy_block_with_outbound(
            2,
            Some(chain[0].header.hash),
            vec![outbound(b"other")],
        );
        let stream = stream::iter(vec![peer_block_msg(&served, 4)]);

        let err = refetched_block(stream, Slot::from(4), 2, chain[1].header.hash)
            .await
            .expect_err("different bytes than the walk saw must be refused");
        assert!(
            err.to_string().contains("different bytes"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn refetch_reports_a_missing_or_undecodable_block_as_retriable() {
        let err = refetched_block(
            stream::iter(vec![undecodable_msg(4)]),
            Slot::from(4),
            2,
            HashType([1; 32]),
        )
        .await
        .expect_err("nothing at the slot decodes to the block");
        assert!(
            err.to_string().contains("no longer serves"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn evidence_from_a_reader_that_died_before_the_wait_does_not_escalate() {
        let verifier = verifier();
        cache_chain(&verifier, linked_chain(2)).await;
        verifier.watch.register(PEER_ZONE);
        verifier.watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
        tokio::time::sleep(Duration::from_secs(1)).await;

        let err = verifier
            .wait_for_peer_block(PEER_ZONE, 9, 0)
            .await
            .expect_err("still unresolved");
        assert!(matches!(err, PeerBlockError::Unavailable { .. }));
    }

    #[tokio::test]
    async fn peer_snapshots_classify_reader_health() {
        let watch = PeerWatch::default();
        watch.register([1; 32]);
        watch.report_pass([2; 32], &at_tip_report(2, 7));
        watch.report_pass(
            [3; 32],
            &PassReport {
                cursor_slot: Some(3),
                verified_tip: Some(1),
                stuck: Some((4, 3)),
                drained: false,
                drained_at_tip: None,
                lib_slot: None,
                pin_refused: false,
            },
        );
        watch.report_pass(
            [4; 32],
            &PassReport {
                cursor_slot: Some(3),
                verified_tip: Some(1),
                stuck: None,
                drained: true,
                drained_at_tip: None,
                lib_slot: None,
                pin_refused: false,
            },
        );
        watch.mark_halted([5; 32]);
        watch.report_suspended([6; 32]);

        let statuses = watch.statuses();
        let health: Vec<PeerHealth> = statuses.iter().map(|status| status.health).collect();
        assert_eq!(
            health,
            vec![
                PeerHealth::Lagging,
                PeerHealth::Live,
                PeerHealth::Holed,
                PeerHealth::Lagging,
                PeerHealth::Halted,
                PeerHealth::Suspended,
            ],
            "registered-only, at-tip, stuck, drained-behind, halted, suspended"
        );
        assert_eq!(statuses[0].zone, hex::encode([1_u8; 32]));
        assert_eq!(statuses[2].stuck_slot_attempts, 3);
        assert_eq!(statuses[2].cursor_slot, Some(3));
        assert_eq!(statuses[1].verified_tip_block_id, Some(2));
    }

    #[tokio::test]
    async fn unverified_keys_match_what_verification_records() {
        let verifier = verifier();
        cache_chain(&verifier, peer_chain(b"hi")).await;
        let block = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        let verified = verifier
            .verify_block(&block, Slot::from(0))
            .await
            .expect("verifies");
        assert_eq!(
            CrossZoneVerifier::unverified_dispatch_keys(&block),
            verified
        );
    }

    #[tokio::test]
    async fn accept_listed_keys_short_circuit_replays_without_peer_data() {
        let verifier = verifier();
        let block = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        verifier
            .record_seen(CrossZoneVerifier::unverified_dispatch_keys(&block))
            .await;
        verifier
            .verify_block(&block, Slot::from(0))
            .await
            .expect("replay short-circuits on the recorded key");
    }

    #[tokio::test(start_paused = true)]
    async fn an_evicted_block_with_no_refetch_source_waits_rather_than_forging() {
        let verifier = verifier_with_window(1);
        cache_chain_with_slots(&verifier.peers, linked_chain(4)).await;
        assert!(matches!(
            verifier.peers.resolve(PEER_ZONE, 1).await,
            PeerLookup::Evicted { .. }
        ));

        let err = verifier
            .wait_for_peer_block(PEER_ZONE, 1, 0)
            .await
            .expect_err("the refetch cannot succeed without a channel client");
        assert!(
            matches!(err, PeerBlockError::Unavailable { .. }),
            "an evicted body is lag until refetched, not forgery: {err:?}"
        );
        assert!(
            verifier.refetch_attempts.load(Ordering::Relaxed) > 0,
            "each pass counts its refetch attempt"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_refetch_under_full_at_tip_evidence_does_not_escalate() {
        let verifier = verifier_with_window(1);
        cache_chain_with_slots(&verifier.peers, linked_chain(4)).await;
        assert!(matches!(
            verifier.peers.resolve(PEER_ZONE, 1).await,
            PeerLookup::Evicted { .. }
        ));
        verifier.watch.register(PEER_ZONE);
        verifier.watch.report_pass(PEER_ZONE, &at_tip_report(4, 7));

        let wait = verifier.wait_for_peer_block(PEER_ZONE, 1, 7);
        let keep_reporting = async {
            for _ in 0_u32..40 {
                tokio::time::sleep(Duration::from_secs(10)).await;
                verifier.watch.report_pass(PEER_ZONE, &at_tip_report(4, 7));
            }
        };
        let (result, ()) = tokio::join!(wait, keep_reporting);
        assert!(
            matches!(
                result.expect_err("no refetch client is configured, so every refetch fails"),
                PeerBlockError::Unavailable { .. }
            ),
            "an evicted body with a failing refetch stays retriable, never the absence verdict"
        );
        assert_ne!(
            verifier.peer_statuses()[0].health,
            PeerHealth::Halted,
            "no verdict was issued, so the peer is not marked halted"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn each_lookup_class_has_its_own_wait_outcome() {
        let verifier = verifier_with_window(1);
        cache_chain_with_slots(&verifier.peers, linked_chain(4)).await;

        let block = verifier
            .wait_for_peer_block(PEER_ZONE, 4, 0)
            .await
            .expect("a cached body is served");
        assert_eq!(block.header.block_id, 4);

        let before = verifier.refetch_attempts.load(Ordering::Relaxed);
        let evicted_err = verifier
            .wait_for_peer_block(PEER_ZONE, 1, 0)
            .await
            .expect_err("no refetch source is configured");
        assert!(matches!(evicted_err, PeerBlockError::Unavailable { .. }));
        assert!(
            verifier.refetch_attempts.load(Ordering::Relaxed) > before,
            "an evicted id goes to the refetch path"
        );

        let inside_run_err = verifier
            .wait_for_peer_block(PEER_ZONE, 0, 0)
            .await
            .expect_err("an id the walk never certified");
        assert!(matches!(inside_run_err, PeerBlockError::NotOnPeerChain(_)));

        let behind_err = verifier
            .wait_for_peer_block(PEER_ZONE, 9, 0)
            .await
            .expect_err("the reader has not read this far");
        assert!(matches!(behind_err, PeerBlockError::Unavailable { .. }));
    }
}
