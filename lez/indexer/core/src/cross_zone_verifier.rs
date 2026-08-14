use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use common::{
    block::{Block, PeerChainTip},
    transaction::LeeTransaction,
};
use cross_zone::{
    EmissionSource, Link, OffChain, StallState, alerts_at, build_dispatch_from_emission,
    equivocation_report, extract_emission, link_to_tip, screen_peer_block,
};
use cross_zone_inbox_core::{
    CrossZoneMessage, Instruction as InboxInstruction, MessageKey, ZoneId, message_key,
};
use futures::{Stream, StreamExt as _};
use lee::{GENESIS_BLOCK_ID, PublicKey};
use log::{debug, error, warn};
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use logos_blockchain_zone_sdk::{
    CommonHttpClient, Slot, ZoneMessage,
    adapter::{Node as _, NodeHttpClient},
    indexer::ZoneIndexer,
};
use tokio::{sync::RwLock, time::Instant};

use crate::{
    config::IndexerConfig,
    status::{PeerHealth, PeerStatus},
};

/// How often the verifier logs that it is still waiting on a lagging peer reader,
/// so a stuck wait is observable without rejecting a legitimate message.
const LAG_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// How long to wait for a referenced peer block before giving up on this pass.
/// Generous, since ordinary L1 finality lag delays a peer block by minutes.
/// Expiry is not a rejection: the caller retries the same block, so the cost of a
/// premature expiry is one repeated pass.
const PEER_BLOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(300);

/// How long each wait iteration sleeps. Also the unit the elapsed counter is
/// advanced by, so `waited` counts sleeps rather than wall time and, since a
/// sleep can overshoot, understates it.
const PEER_BLOCK_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Why a cross-zone dispatch could not be verified.
///
/// A forgery is terminal and must stop the block applying; an unavailable peer
/// block is transient and must be retried, or a lagging peer reader would
/// permanently halt ingestion.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CrossZoneVerifyError {
    /// The dispatch does not match the peer's finalized chain.
    #[error("{0}")]
    Forged(ForgedDispatch),
    /// The referenced peer block has not been read yet.
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

/// A dispatch judged permanently invalid: its source coordinates plus the
/// verdict, which is what the caller's halt record persists.
#[derive(Debug)]
pub struct ForgedDispatch {
    pub src_zone: ZoneId,
    pub src_block_id: u64,
    pub src_tx_index: u32,
    pub verdict: String,
}

impl Display for ForgedDispatch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "forged cross-zone dispatch from zone {} block {} tx {}: {}",
            hex::encode(self.src_zone),
            self.src_block_id,
            self.src_tx_index,
            self.verdict
        )
    }
}

/// Why [`CrossZoneVerifier::wait_for_peer_block`] could not produce the
/// referenced peer block.
#[derive(Debug)]
enum PeerBlockError {
    /// Judged permanently: the id is not on the peer's chain. The caller maps
    /// this onto the dispatch's coordinates as [`CrossZoneVerifyError::Forged`].
    NotOnPeerChain(String),
    /// Not judged either way yet; the caller retries.
    Unavailable { waited: Duration },
}

/// The replay key plus the source block: what the inbox treats as one delivery.
///
/// Skipping re-derivation on the key alone would wave through a dispatch the
/// guest refuses, parking the block and holding ingestion.
pub type SeenKey = (MessageKey, [u8; 32]);

/// One peer zone's cached blocks, plus how far this reader has read them as an
/// unbroken hash-linked run from the peer's genesis.
#[derive(Default)]
struct PeerChain {
    blocks: HashMap<u64, Block>,
    /// The head of the run: the highest id such that every block from
    /// [`GENESIS_BLOCK_ID`] up to it has been read and each links to its
    /// predecessor, plus that block's hash, pinned when [`Self::extend_prefix`]
    /// walked it. `None` until genesis is read.
    ///
    /// The id, not `max(blocks.keys())`, is what the forgery test gates on: a
    /// peer picks its own `block_id`s, and an id that does not continue the run
    /// cannot advance the run.
    ///
    /// The hash is stored rather than re-read from `blocks`, so the tip
    /// survives the tip block leaving the map; re-deriving it there would make
    /// any future cache bounding misclassify the next honest block as
    /// [`OffChain::NotTheGenesis`] and freeze the run.
    ///
    /// The link it walks means something only because [`accept_peer_block`]
    /// recomputes `header.hash` and checks the pinned key before anything is
    /// cached. Without that it compared two fields the peer wrote.
    verified_prefix: Option<PeerChainTip>,
}

impl PeerChain {
    /// The id that would extend the verified run.
    const fn next_expected(&self) -> u64 {
        match self.verified_prefix {
            Some(tip) => tip.block_id.saturating_add(1),
            None => GENESIS_BLOCK_ID,
        }
    }

    /// Extends the verified run as far as the cached blocks allow, off the same
    /// [`link_to_tip`] the watcher follows. The tip is pinned off [`Link::Next`],
    /// whose hash [`accept_peer_block`] proved is the recomputed one.
    fn extend_prefix(&mut self) {
        while let Some(next) = self.blocks.get(&self.next_expected()) {
            match link_to_tip(self.tip().as_ref(), next, next.header.hash) {
                Link::Next(block_hash) => {
                    self.verified_prefix = Some(PeerChainTip {
                        block_id: next.header.block_id,
                        block_hash,
                    });
                }
                Link::AlreadySeen { .. } | Link::OffChain(_) => return,
            }
        }
    }

    /// The tip pinning the verified run. `None` before the peer's genesis is
    /// held.
    const fn tip(&self) -> Option<PeerChainTip> {
        self.verified_prefix
    }
}

/// What one consistent look at the peer cache says about a referenced block.
enum PeerLookup {
    /// Held, and inside the run verified from the peer's genesis.
    Cached(Box<Block>),
    /// Inside the verified run but not held, so it is not on the peer chain.
    InsideRun,
    /// The reader has not verified this far yet.
    Behind,
}

/// Cache of finalized peer-zone blocks, filled by per-peer reader tasks and read
/// by the verifier to re-derive cross-zone dispatch transactions.
#[derive(Clone, Default)]
struct PeerBlocks {
    chains: Arc<RwLock<HashMap<ZoneId, PeerChain>>>,
}

impl PeerBlocks {
    /// Caches `block` if it is the next one this reader needs, and says whether
    /// it was newly cached.
    ///
    /// Sequential, exactly like the watcher on the sequencer side. Caching ahead
    /// of the run looks harmless, since an id that does not continue the run
    /// cannot advance it, but it is not: when the predecessor later arrives the
    /// prefix walks straight through the block held ahead, while the watcher,
    /// which reads strictly in order and never reconsiders what it passed over,
    /// has already discarded it. The two then hold different blocks at one id,
    /// and the next dispatch naming it re-derives against the wrong one and
    /// halts ingestion. Refusing to look ahead is what keeps the two in step.
    ///
    /// First write wins at every id but one. An identical re-read is a no-op,
    /// which the reader does on every slot retry. A differing block inside the
    /// run is equivocation, and replacing it is the remote halt from #648: the
    /// prefix certified the old value, so the next dispatch naming that id
    /// re-derives against the new one and reads as forged.
    ///
    /// The exception is the one id that would extend the run. Holding the first
    /// arrival there is its own trap: a peer inscribing a block that claims that
    /// id and does not continue the chain locks it out for good, since the
    /// honest block is refused when it lands and the run can never walk past it,
    /// and the channel is append-only so a restart replays the same order and
    /// holds the same block. There, and only there, a block that continues the
    /// run displaces one that does not.
    async fn insert(&self, zone: ZoneId, block: Block) -> bool {
        let mut chains = self.chains.write().await;
        let chain = chains.entry(zone).or_default();

        // `block` was screened on the way in, so `header.hash` is its
        // recomputed hash and is what the synthesized tip pins.
        let link = link_to_tip(chain.tip().as_ref(), &block, block.header.hash);
        let continues_the_run = matches!(link, Link::Next(_));
        match link {
            // Ahead of the run, or a first read that is not the peer's genesis.
            Link::OffChain(OffChain::NotTheGenesis { .. } | OffChain::SkipsAhead { .. }) => {
                debug!(
                    "Peer reader for {} not caching block {}: only block {} continues the run verified from that peer's genesis.",
                    hex::encode(zone),
                    block.header.block_id,
                    chain.next_expected()
                );
                false
            }
            Link::AlreadySeen { .. } => {
                // Every id the run has walked is held; below the peer's genesis
                // nothing is, and an id on no chain the run can ever walk must
                // not be cached, or it would resolve as the peer's own block
                // for ever after.
                match chain.blocks.get(&block.header.block_id) {
                    Some(held) if held.header.hash == block.header.hash => false,
                    Some(held) => {
                        error!(
                            "{}",
                            equivocation_report(
                                &zone,
                                block.header.block_id,
                                held.header.hash,
                                block.header.hash
                            )
                        );
                        false
                    }
                    None => {
                        debug!(
                            "Peer reader for {} not caching block {}: below the peer's genesis, on no chain the run can walk.",
                            hex::encode(zone),
                            block.header.block_id
                        );
                        false
                    }
                }
            }
            // The one id that would extend the run. A block linking to the tip
            // continues it; one that does not is cached only while the id is
            // free, first write wins.
            Link::Next(_) | Link::OffChain(OffChain::DoesNotLink { .. }) => {
                if let Some(held) = chain.blocks.get(&block.header.block_id) {
                    if held.header.hash == block.header.hash {
                        return false;
                    }
                    if !continues_the_run {
                        error!(
                            "{}",
                            equivocation_report(
                                &zone,
                                block.header.block_id,
                                held.header.hash,
                                block.header.hash
                            )
                        );
                        return false;
                    }
                    log::info!(
                        "Peer zone {} block {}: replacing held block {} with {}, which continues the verified run where the held one never could.",
                        hex::encode(zone),
                        block.header.block_id,
                        held.header.hash,
                        block.header.hash
                    );
                }
                chain.blocks.insert(block.header.block_id, block);
                chain.extend_prefix();
                true
            }
        }
    }

    /// Resolves `block_id` under a single read lock.
    ///
    /// Cached is not the same as verified, and only the second may be delivered
    /// from. A peer writes its own block ids, and a block enters the cache on
    /// its own hash and signature alone, so one claiming an id its chain never
    /// reached is cached like any other. The run walked from the peer's genesis
    /// is what says the peer built it. A block outside that run therefore reads
    /// as one the reader has not got to, which stalls the dispatch naming it
    /// rather than certifying it, and a peer inscribing a block ahead of its
    /// chain cannot get a message delivered under an id it has not reached.
    ///
    /// One lock, because answering "is it cached?" and "is it inside the run?"
    /// separately races with the peer reader: an insert landing between them
    /// reads as absent-and-inside-the-run, which is the forgery signal, for a
    /// block that is in fact cached. That is the normal steady state, a waiting
    /// verifier and the block it waits for arriving.
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
        chain
            .blocks
            .get(&block_id)
            .map_or(PeerLookup::InsideRun, |block| {
                PeerLookup::Cached(Box::new(block.clone()))
            })
    }

    #[cfg(test)]
    async fn get(&self, zone: ZoneId, block_id: u64) -> Option<Block> {
        self.chains
            .read()
            .await
            .get(&zone)
            .and_then(|chain| chain.blocks.get(&block_id).cloned())
    }

    /// How far this reader has read `zone` as an unbroken run from genesis, or
    /// `None` if it has not read the peer's genesis block yet.
    async fn verified_prefix(&self, zone: ZoneId) -> Option<u64> {
        self.chains
            .read()
            .await
            .get(&zone)
            .and_then(|chain| chain.verified_prefix)
            .map(|tip| tip.block_id)
    }
}

/// The evidence backing a verified-absence verdict.
#[derive(Clone, Copy, Debug)]
struct AbsenceEvidence {
    channel_tip_slot: u64,
    drained_passes: u64,
    verified_tip: Option<u64>,
    lib_slot: u64,
}

/// One reader pass, as folded into [`PeerWatch`].
struct PassReport {
    cursor_slot: Option<u64>,
    verified_tip: Option<u64>,
    stuck: Option<(u64, u32)>,
    drained: bool,
    /// The channel tip slot, present only when the pass drained with the
    /// cursor at it.
    drained_at_tip: Option<u64>,
    /// The endpoint's LIB slot, read only on an at-tip pass.
    lib_slot: Option<u64>,
}

/// One peer reader's live diagnostics.
#[derive(Clone, Copy, Debug, Default)]
struct PeerDiagnostics {
    cursor_slot: Option<u64>,
    verified_tip: Option<u64>,
    stuck: Option<(u64, u32)>,
    last_pass_drained: bool,
    halted: bool,
    evidence: TipEvidence,
}

impl PeerDiagnostics {
    const fn health(&self) -> PeerHealth {
        if self.halted {
            PeerHealth::Halted
        } else if self.stuck.is_some() {
            PeerHealth::Holed
        } else if self.last_pass_drained && self.evidence.since.is_some() {
            PeerHealth::Live
        } else {
            PeerHealth::Lagging
        }
    }
}

/// Per-peer diagnostics shared between the reader tasks (writers), the
/// verifier's escalation check, and status snapshots (readers).
#[derive(Clone, Default)]
struct PeerWatch {
    peers: Arc<Mutex<HashMap<ZoneId, PeerDiagnostics>>>,
}

impl PeerWatch {
    /// Positive evidence that the peer chain holds nothing past what the
    /// reader verified: an at-tip run intact since before `wait_started`, with
    /// at least one pass after it (a reader that died before the wait proves
    /// nothing about it), from a view at least as fresh as `local_slot`, the
    /// halting local block's inscription slot. `None` says keep waiting.
    fn confirmed_absence(
        &self,
        zone: ZoneId,
        wait_started: Instant,
        local_slot: u64,
    ) -> Option<AbsenceEvidence> {
        let peers = self.lock();
        let entry = peers.get(&zone)?;
        let evidence = entry.evidence;
        if evidence.since? > wait_started || evidence.latest? < wait_started {
            return None;
        }
        // The referenced peer block predates the local block's inscription, so
        // a view at least that fresh refutes it; a staler view (e.g. a lagging
        // Bedrock replica serving both this check and the reader) proves
        // nothing.
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

    fn lock(&self) -> MutexGuard<'_, HashMap<ZoneId, PeerDiagnostics>> {
        self.peers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Unsticks a halted mark once the peer serves again: the next successful
    /// rederive for the zone, or an accept-list acceptance.
    fn clear_halted(&self, zone: ZoneId) {
        self.lock().entry(zone).or_default().halted = false;
    }

    fn mark_halted(&self, zone: ZoneId) {
        self.lock().entry(zone).or_default().halted = true;
    }

    /// Registers a configured peer so it appears in snapshots before its
    /// first pass.
    fn register(&self, zone: ZoneId) {
        self.lock().entry(zone).or_default();
    }

    /// Folds in a pass that never produced a stream. It read nothing, so it
    /// says nothing about the channel tip and breaks the evidence run.
    fn report_failed_pass(&self, zone: ZoneId) {
        let mut peers = self.lock();
        let entry = peers.entry(zone).or_default();
        entry.last_pass_drained = false;
        entry.evidence = TipEvidence::default();
    }

    fn report_pass(&self, zone: ZoneId, report: &PassReport) {
        let mut peers = self.lock();
        let entry = peers.entry(zone).or_default();
        entry.cursor_slot = report.cursor_slot;
        entry.verified_tip = report.verified_tip;
        entry.stuck = report.stuck;
        entry.last_pass_drained = report.drained;
        if let Some(tip_slot) = report.drained_at_tip {
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

    /// Snapshots every registered peer, ordered by zone id.
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

/// The reader's caught-up evidence: an unbroken run of passes that drained
/// with the cursor at the peer channel's tip. Any stall, failed pass, lag
/// behind the tip, or tip-read failure clears it, so a run intact across a
/// whole wait window is positive evidence the channel holds nothing the reader
/// has not verified.
#[derive(Clone, Copy, Debug, Default)]
struct TipEvidence {
    since: Option<Instant>,
    latest: Option<Instant>,
    drained_passes: u64,
    channel_tip_slot: Option<u64>,
    /// Highest LIB slot observed on the run's at-tip passes: how fresh the
    /// endpoint's view is, gating escalation against a stale replica.
    lib_slot: Option<u64>,
}

/// The indexer-side Option B verifier.
///
/// For every cross-zone dispatch in a block it re-derives the transaction from
/// the peer's finalized block and rejects it if the bytes differ (a forgery), so
/// delivery no longer relies on trusting the sequencer. A replay of an
/// already-delivered message is accepted, since the inbox no-ops it on chain.
#[derive(Clone)]
pub struct CrossZoneVerifier {
    self_zone: ZoneId,
    /// Pinned block-signing key per peer zone, enforced during re-derivation.
    /// One key per peer is sufficient while a zone has a single sequencer; key
    /// sets with rotation come in with decentralized sequencing. The pin is
    /// largely redundant given Bedrock's turn-based write authorization, so it is
    /// optional: a peer with no configured key is not signature-checked.
    peer_pubkeys: HashMap<ZoneId, PublicKey>,
    peers: PeerBlocks,
    seen: Arc<RwLock<HashSet<SeenKey>>>,
    watch: PeerWatch,
}

impl CrossZoneVerifier {
    /// Builds the verifier and spawns one peer reader per configured peer.
    /// Returns `None` when cross-zone messaging is disabled.
    pub fn start(config: &IndexerConfig) -> Option<Self> {
        let cross_zone = config.cross_zone.as_ref()?;
        let self_zone: ZoneId = *config.channel_id.as_ref();
        let peers = PeerBlocks::default();
        let watch = PeerWatch::default();
        let mut peer_pubkeys = HashMap::new();

        for peer in &cross_zone.peers {
            let node = NodeHttpClient::new(
                CommonHttpClient::new(config.bedrock_config.auth.clone().map(Into::into)),
                config.bedrock_config.addr.clone(),
            );
            // The reader moves `node` into its `ZoneIndexer`; this clone is its
            // own handle for the channel-tip reads behind the evidence run.
            let tip_node = node.clone();
            if let Some(bytes) = peer.expected_block_signing_pubkey {
                let pubkey = PublicKey::try_new(bytes)
                    .expect("configured peer block-signing pubkey is a valid key");
                peer_pubkeys.insert(peer.channel_id, pubkey);
            }
            watch.register(peer.channel_id);
            tokio::spawn(read_peer(
                ZoneIndexer::new(ChannelId::from(peer.channel_id), node),
                tip_node,
                peer.channel_id,
                peer_pubkeys.get(&peer.channel_id).cloned(),
                peers.clone(),
                watch.clone(),
                config.consensus_info_polling_interval,
            ));
        }

        Some(Self {
            self_zone,
            peer_pubkeys,
            peers,
            seen: Arc::new(RwLock::new(HashSet::new())),
            watch,
        })
    }

    /// Per-peer reader snapshots for status reporting.
    #[must_use]
    pub fn peer_statuses(&self) -> Vec<PeerStatus> {
        self.watch.statuses()
    }

    /// The seen keys of every dispatch in `block`, decoded without any
    /// verification. Only for the operator accept-list: recording them makes a
    /// later replay short-circuit exactly as a verified delivery's would.
    #[must_use]
    pub fn unverified_dispatch_keys(block: &Block) -> Vec<SeenKey> {
        block
            .body
            .transactions
            .iter()
            .filter_map(|tx| Self::decode_dispatch(tx).as_ref().map(seen_key))
            .collect()
    }

    /// [`Self::unverified_dispatch_keys`] plus unsticking each dispatch's
    /// source zone from a halted mark: an operator acceptance supersedes the
    /// verdict that marked the zone. The caller records the keys only once
    /// the block applies.
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

    /// Verifies every cross-zone dispatch in a block, returning the keys to mark
    /// seen, or the reason verification could not complete. `inscription_slot`
    /// is the L1 slot the block was inscribed at, bounding how fresh a peer
    /// view must be before a verified-absence verdict may fire.
    ///
    /// [`CrossZoneVerifyError::Forged`] means the caller must halt ingestion;
    /// [`CrossZoneVerifyError::PeerUnavailable`] means the caller must hold its
    /// read cursor and retry, since the block is not yet judged either way.
    ///
    /// The caller MUST record the returned keys via [`Self::record_seen`] only
    /// after the block applies, so the seen-set mirrors the inbox's on-chain
    /// seen-shard. Marking a key from a block that never applies would let a later
    /// forged dispatch reuse it to skip re-derivation while the inbox delivers the
    /// forgery. A key already seen is a replay the inbox no-ops, so it is accepted
    /// without re-derivation rather than halting on a legitimate re-delivery.
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
                    "Skipping already-seen cross-zone dispatch from zone {} block {} tx {} (replay no-op)",
                    hex::encode(msg.src_zone),
                    msg.src_block_id,
                    msg.src_tx_index
                );
                continue;
            }

            let expected = self.rederive(&msg, inscription_slot.into_inner()).await?;
            if LeeTransaction::Public(expected) != *tx {
                return Err(forged(&msg, "re-derivation mismatch".to_owned()));
            }

            log::info!(
                "Verified cross-zone dispatch from zone {} block {} tx {}",
                hex::encode(msg.src_zone),
                msg.src_block_id,
                msg.src_tx_index
            );
            verified.push(key);
        }
        Ok(verified)
    }

    /// Marks the given dispatch keys seen, so a later replay of them is accepted
    /// without re-derivation. Call only after the block that carried them has been
    /// applied on chain (see [`Self::verify_block`]).
    pub async fn record_seen(&self, keys: Vec<SeenKey>) {
        if keys.is_empty() {
            return;
        }
        self.seen.write().await.extend(keys);
    }

    /// Decodes a transaction into the cross-zone message it dispatches, or `None`
    /// if it is not an inbox dispatch.
    fn decode_dispatch(tx: &LeeTransaction) -> Option<CrossZoneMessage> {
        let LeeTransaction::Public(public_tx) = tx else {
            return None;
        };
        if public_tx.message().program_id != programs::cross_zone_inbox().id() {
            return None;
        }
        match risc0_zkvm::serde::from_slice::<InboxInstruction, _>(
            &public_tx.message().instruction_data,
        ) {
            Ok(InboxInstruction::Dispatch(msg)) => Some(msg),
            // Only a dispatch carries a cross-zone message to re-derive; a genesis
            // `InitConfig` is not verifier-relevant.
            Ok(InboxInstruction::InitConfig(_)) | Err(_) => None,
        }
    }

    /// Re-derives the dispatch transaction the watcher should have injected for
    /// `msg`, reading the source emission from the peer's finalized block.
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

        // Equivocation defense: the source block must be signed by the peer's
        // pinned block-signing key, not merely inscribed on the channel.
        if let Some(expected) = self.peer_pubkeys.get(&msg.src_zone)
            && !peer_block.is_signed_by(expected)
        {
            return Err(forged(
                msg,
                "peer block is not signed by the pinned block-signing key".to_owned(),
            ));
        }

        // Everything below is a property of the peer block just read, so a
        // mismatch is the dispatch lying about it, not a transient condition.
        let emission_tx = peer_block
            .body
            .transactions
            .get(usize::try_from(msg.src_tx_index).expect("u32 index fits in usize"))
            .ok_or_else(|| forged(msg, "src_tx_index out of range in peer block".to_owned()))?;

        let LeeTransaction::Public(emission_tx) = emission_tx else {
            return Err(forged(
                msg,
                "peer emission transaction is not public".to_owned(),
            ));
        };
        let message = emission_tx.message();
        let emission =
            extract_emission(message.program_id, &message.instruction_data).ok_or_else(|| {
                forged(
                    msg,
                    "peer transaction at src_tx_index is not a recognized emitter".to_owned(),
                )
            })?;

        if emission.target_zone != self.self_zone {
            return Err(forged(
                msg,
                "peer emission targets a different zone".to_owned(),
            ));
        }

        // The peer chain served this rederivation, so a halted mark against
        // the zone no longer holds.
        self.watch.clear_halted(msg.src_zone);

        // Recomputed rather than read from `msg`, which would make the field
        // attest to itself.
        Ok(build_dispatch_from_emission(
            &EmissionSource {
                src_zone: msg.src_zone,
                src_block_id: msg.src_block_id,
                src_block_hash: peer_block.recompute_hash().0,
                src_tx_index: msg.src_tx_index,
                src_program_id: message.program_id,
            },
            emission.target_program_id,
            &emission.target_accounts,
            emission.payload,
        ))
    }

    /// Resolves the referenced peer block, distinguishing forgery from lag.
    ///
    /// A `block_id` inside the run verified from the peer's genesis (see
    /// [`PeerChain::verified_prefix`]) that we do not hold does not exist on the
    /// peer chain, so reject it. Otherwise the reader has not reached it, so
    /// wait, and give up after [`PEER_BLOCK_WAIT_TIMEOUT`] rather than block
    /// ingestion forever. A reference to a block the peer never produced
    /// ordinarily stalls rather than being rejected, since it is
    /// indistinguishable from a block the peer has not produced yet; either way
    /// it is never applied. The one exception is evidence-backed: a reader
    /// whose at-tip run (see [`TipEvidence`]) covered this whole wait read
    /// everything the channel holds, so an id still beyond the verified tip is
    /// on no chain the peer inscribed, and the wait ends in a permanent
    /// verdict instead of another retry. `local_slot`, the halting local
    /// block's inscription slot, bounds how fresh that evidence must be (see
    /// [`PeerWatch::confirmed_absence`]).
    async fn wait_for_peer_block(
        &self,
        zone: ZoneId,
        block_id: u64,
        local_slot: u64,
    ) -> Result<Block, PeerBlockError> {
        let wait_started = Instant::now();
        let mut waited = Duration::ZERO;
        loop {
            match self.peers.resolve(zone, block_id).await {
                PeerLookup::Cached(block) => return Ok(*block),
                // A backstop, not the live path: every id inside the run is
                // cached by construction. Bounding the cache must preserve that
                // or track a floor alongside the prefix, since an evicted block
                // is not a forged one and reporting it as forged would halt a
                // legitimate dispatch.
                PeerLookup::InsideRun => {
                    return Err(PeerBlockError::NotOnPeerChain(format!(
                        "peer zone {} chain is verified past block {block_id} but it is absent",
                        hex::encode(zone)
                    )));
                }
                PeerLookup::Behind => {}
            }
            if waited >= PEER_BLOCK_WAIT_TIMEOUT {
                if let Some(evidence) = self.watch.confirmed_absence(zone, wait_started, local_slot)
                {
                    self.watch.mark_halted(zone);
                    return Err(PeerBlockError::NotOnPeerChain(absence_verdict(
                        zone, block_id, &evidence,
                    )));
                }
                return Err(PeerBlockError::Unavailable { waited });
            }
            if !waited.is_zero() && waited.as_secs().is_multiple_of(LAG_LOG_INTERVAL.as_secs()) {
                log::info!(
                    "Waiting for peer zone {} to finalize block {} ({}s); reader is behind",
                    hex::encode(zone),
                    block_id,
                    waited.as_secs()
                );
            }
            tokio::time::sleep(PEER_BLOCK_POLL_INTERVAL).await;
            waited = waited.saturating_add(PEER_BLOCK_POLL_INTERVAL);
        }
    }
}

/// The outcome of one pass over a peer's message stream.
#[derive(Debug, PartialEq, Eq)]
struct PeerPass {
    /// Where the next pass resumes from.
    cursor: Option<Slot>,
    /// Set when the pass ended early on a message that would not decode.
    stalled_at: Option<Slot>,
}

/// The verdict text for an id refuted by an at-tip reader: what the reader saw
/// against what the dispatch claimed.
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

/// The channel tip slot, only when `cursor` has reached it. `None` on a read
/// failure, an absent channel, or a cursor behind the tip, all of which break
/// the caught-up evidence run rather than count toward it.
async fn channel_tip_reached(
    node: &NodeHttpClient,
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

/// The endpoint's LIB slot, or `None` on a read failure. Read on at-tip
/// passes as freshness evidence for the escalation guard in
/// [`PeerWatch::confirmed_absence`].
async fn observed_lib_slot(node: &NodeHttpClient) -> Option<u64> {
    let info = node.consensus_info().await.ok()?;
    Some(info.cryptarchia_info.lib_slot.into_inner())
}

/// A permanent verdict against `msg`, carrying its coordinates for the halt
/// record.
const fn forged(msg: &CrossZoneMessage, verdict: String) -> CrossZoneVerifyError {
    CrossZoneVerifyError::Forged(ForgedDispatch {
        src_zone: msg.src_zone,
        src_block_id: msg.src_block_id,
        src_tx_index: msg.src_tx_index,
        verdict,
    })
}

fn seen_key(msg: &CrossZoneMessage) -> SeenKey {
    (
        message_key(&msg.src_zone, msg.src_block_id, msg.src_tx_index),
        msg.src_block_hash,
    )
}

/// Whether a block read off a peer's channel may enter the cache, screened by
/// the same [`screen_peer_block`] policy the watcher applies. [`ScreenRefusal`]
/// says why each check exists.
///
/// [`ScreenRefusal`]: cross_zone::ScreenRefusal
fn accept_peer_block(
    block: &Block,
    peer_zone: ZoneId,
    expected_pubkey: Option<&PublicKey>,
) -> bool {
    match screen_peer_block(block, expected_pubkey) {
        Ok(_) => true,
        Err(refusal) => {
            warn!(
                "Peer reader dropping block from {}: {refusal}",
                hex::encode(peer_zone)
            );
            false
        }
    }
}

/// Reads a peer zone's finalized blocks from Bedrock into the shared cache,
/// reporting each pass into `watch`.
#[expect(
    clippy::infinite_loop,
    reason = "the peer reader runs for the lifetime of the indexer process"
)]
async fn read_peer(
    zone_indexer: ZoneIndexer<NodeHttpClient>,
    tip_node: NodeHttpClient,
    peer_zone: ZoneId,
    expected_pubkey: Option<PublicKey>,
    peers: PeerBlocks,
    watch: PeerWatch,
    poll_interval: Duration,
) {
    log::info!(
        "Cross-zone peer reader started for {}",
        hex::encode(peer_zone)
    );

    let mut cursor = None;
    // In memory only: it says how loud to be about a slot this reader is stuck
    // on.
    let mut stall = StallState::default();
    loop {
        match zone_indexer.next_messages(cursor).await {
            Ok(stream) => {
                let pass = consume_peer_stream(
                    stream,
                    peer_zone,
                    expected_pubkey.as_ref(),
                    &peers,
                    cursor,
                )
                .await;
                cursor = pass.cursor;
                if let Some((slot, attempts)) = stall.after_pass(pass.stalled_at, pass.cursor)
                    && alerts_at(attempts)
                {
                    error!(
                        "Peer reader for {} has been stuck at slot {slot:?} for {attempts} passes. The run verified from that peer's genesis stops below it, so every dispatch naming a later block stalls until this slot can be read.",
                        hex::encode(peer_zone)
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
                    },
                );
            }
            Err(err) => {
                error!(
                    "Peer reader next_messages failed for {}: {err}",
                    hex::encode(peer_zone)
                );
                watch.report_failed_pass(peer_zone);
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Caches the finalized peer blocks carried by `stream`.
///
/// A block that fails to deserialize ends the pass and holds the cursor at the
/// last fully-consumed slot, so the next poll re-reads it and a transient
/// failure heals itself. It is never read past, however long it stays stuck:
/// a hole stops [`PeerChain::verified_prefix`] below it, and since only blocks
/// inside that run may be delivered from, reading on would cache blocks that can
/// never be used while the reader claimed to have caught up. The watcher on the
/// sequencer side stops at the same hole for the same reason.
///
/// The cursor advances only on a slot boundary, since one slot can carry several
/// messages and resuming mid-slot would skip the ones after the failure. This
/// relies on the stream never truncating mid-slot, which holds because the
/// zone-sdk materializes a whole batch before yielding and batches end on slot
/// boundaries.
async fn consume_peer_stream<S>(
    stream: S,
    peer_zone: ZoneId,
    expected_pubkey: Option<&PublicKey>,
    peers: &PeerBlocks,
    resume_from: Option<Slot>,
) -> PeerPass
where
    S: Stream<Item = (ZoneMessage, Slot)>,
{
    let mut stream = std::pin::pin!(stream);
    let mut cursor = resume_from;
    // The slot being consumed: cached so far, but there may be more to come.
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
                // Before caching, not when a dispatch names it: an unchecked
                // block steers the prefix, and by then the damage is a halt.
                if accept_peer_block(&block, peer_zone, expected_pubkey) {
                    peers.insert(peer_zone, block).await;
                }
            }
            Err(err) => {
                error!(
                    "Peer reader failed to deserialize block from {} at slot {slot:?}: {err}. Holding the cursor and retrying.",
                    hex::encode(peer_zone)
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

#[cfg(test)]
mod tests {
    use common::{HashType, test_utils::produce_dummy_block};
    use cross_zone::test_utils::{linked_chain_to, ping_emission};
    use futures::stream;
    use lee::{PrivateKey, PublicKey};
    use logos_blockchain_core::mantle::ops::channel::{MsgId, inscribe::Inscription};
    use logos_blockchain_zone_sdk::ZoneBlock;
    use ping_core::{ping_record_pda, receiver_config_account_id};

    use super::*;

    const SELF_ZONE: ZoneId = [1; 32];
    const PEER_ZONE: ZoneId = [2; 32];
    const PEER_BLOCK_ID: u64 = 5;
    /// The peer's run has to start at its genesis, or every test built on
    /// [`peer_chain`] stalls for the full peer-block timeout before failing.
    const _: () = assert!(PEER_BLOCK_ID >= GENESIS_BLOCK_ID);

    fn verifier() -> CrossZoneVerifier {
        verifier_with_pinned_keys(HashMap::new())
    }

    fn verifier_with_pinned_keys(peer_pubkeys: HashMap<ZoneId, PublicKey>) -> CrossZoneVerifier {
        CrossZoneVerifier {
            self_zone: SELF_ZONE,
            peer_pubkeys,
            peers: PeerBlocks::default(),
            seen: Arc::new(RwLock::new(HashSet::new())),
            watch: PeerWatch::default(),
        }
    }

    /// A `ping_sender` emission addressed to `SELF_ZONE` carrying `payload`.
    fn emission(payload: &[u8]) -> LeeTransaction {
        ping_emission(SELF_ZONE, programs::ping_receiver().id(), payload)
    }

    /// A peer-stream item inscribing `data` at `slot`.
    fn peer_msg(data: Vec<u8>, slot: u64) -> (ZoneMessage, Slot) {
        (
            ZoneMessage::Block(ZoneBlock {
                id: MsgId::from([0; 32]),
                data: Inscription::try_from(data).expect("test inscription is within bounds"),
            }),
            Slot::from(slot),
        )
    }

    /// A hash-linked chain of `len` blocks from genesis, each carrying a `b"hi"`
    /// emission. Only a chain built this way advances the verified prefix.
    fn linked_chain(len: u64) -> Vec<Block> {
        linked_chain_to(
            GENESIS_BLOCK_ID.saturating_add(len).saturating_sub(1),
            |_| vec![emission(b"hi")],
        )
    }

    /// A peer-stream item carrying `block`.
    fn peer_block_msg(block: &Block, slot: u64) -> (ZoneMessage, Slot) {
        peer_msg(borsh::to_vec(block).expect("block serializes"), slot)
    }

    /// A hash-linked run from the peer's genesis whose last block,
    /// `PEER_BLOCK_ID`, carries a `payload` emission. The run is what makes that
    /// block deliverable.
    fn peer_chain(payload: &[u8]) -> Vec<Block> {
        linked_chain_to(PEER_BLOCK_ID, |block_id| {
            vec![if block_id == PEER_BLOCK_ID {
                emission(payload)
            } else {
                emission(b"hi")
            }]
        })
    }

    /// Caches a run so its last block sits inside the verified prefix.
    async fn cache_chain(verifier: &CrossZoneVerifier, chain: Vec<Block>) {
        for block in chain {
            verifier.peers.insert(PEER_ZONE, block).await;
        }
    }

    /// A peer-stream item whose inscription is not a decodable block.
    fn undecodable_msg(slot: u64) -> (ZoneMessage, Slot) {
        peer_msg(b"not a block".to_vec(), slot)
    }

    /// The dispatch a watcher would inject for a `PEER_BLOCK_ID` emission of `payload`.
    fn dispatch(payload: &[u8]) -> LeeTransaction {
        dispatch_naming_block_hash(payload, source_block_hash(payload))
    }

    /// The recomputed hash of the `PEER_BLOCK_ID` block carrying `payload`,
    /// which is what an honest watcher puts in the dispatch.
    fn source_block_hash(payload: &[u8]) -> [u8; 32] {
        peer_chain(payload)
            .last()
            .expect("chain reaches PEER_BLOCK_ID")
            .recompute_hash()
            .0
    }

    fn dispatch_naming_block_hash(payload: &[u8], src_block_hash: [u8; 32]) -> LeeTransaction {
        let receiver_id = programs::ping_receiver().id();
        LeeTransaction::Public(build_dispatch_from_emission(
            &EmissionSource {
                src_zone: PEER_ZONE,
                src_block_id: PEER_BLOCK_ID,
                src_block_hash,
                src_tx_index: 0,
                src_program_id: programs::ping_sender().id(),
            },
            receiver_id,
            &[
                receiver_config_account_id(receiver_id).into_value(),
                ping_record_pda(receiver_id).into_value(),
            ],
            payload.to_vec(),
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

        // Only the claimed source hash is wrong. Detectable because the verifier
        // recomputes it from the resolved block instead of reading the field.
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
        // The peer block carries the real emission, but the block claims a
        // different payload, so re-derivation does not reproduce it.
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
    async fn verifies_dispatch_signed_by_the_pinned_peer_key() {
        // produce_dummy_block signs with PrivateKey([37; 32]); pin its pubkey.
        let signer = PublicKey::new_from_private_key(&PrivateKey::try_new([37; 32]).unwrap());
        let mut keys = HashMap::new();
        keys.insert(PEER_ZONE, signer);
        let verifier = verifier_with_pinned_keys(keys);
        cache_chain(&verifier, peer_chain(b"hi")).await;

        let block = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        verifier
            .verify_block(&block, Slot::from(0))
            .await
            .expect("a dispatch from the pinned signer verifies");
    }

    #[tokio::test]
    async fn rejects_dispatch_from_a_block_not_signed_by_the_pinned_key() {
        // Pin a different key than the one that signed the peer block.
        let mut keys = HashMap::new();
        keys.insert(PEER_ZONE, PublicKey::try_new([42; 32]).unwrap());
        let verifier = verifier_with_pinned_keys(keys);
        cache_chain(&verifier, peer_chain(b"hi")).await;

        let block = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        let err = verifier
            .verify_block(&block, Slot::from(0))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("pinned"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn accepts_replayed_dispatch_as_noop() {
        let verifier = verifier();
        cache_chain(&verifier, peer_chain(b"hi")).await;

        let first = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        let keys = verifier
            .verify_block(&first, Slot::from(0))
            .await
            .expect("first delivery verifies");
        // Mark the delivery seen, as the ingest loop does once the block applies.
        verifier.record_seen(keys).await;

        // A payload that cannot re-derive, under the key just recorded, which
        // now names the source block as well as the coordinates. Accepted only
        // by the seen-key short circuit, since the inbox no-ops it on chain;
        // `unaccepted_dispatch_does_not_poison_seen` asserts the same input is
        // rejected when the key was never recorded, which is what makes this one
        // about the short circuit rather than re-derivation.
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
            .expect("a replay is accepted as an on-chain no-op");
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

        // Same coordinates as the delivery just seen, different source block.
        // The inbox refuses rather than no-ops it, so skipping re-derivation
        // would wave through a dispatch that parks the block.
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
        // A dispatch verified in a block that never applies (e.g. one that parks)
        // must not be marked seen. Otherwise a later forged dispatch could reuse
        // its key to skip re-derivation, while the inbox, never having recorded
        // the key on chain, would deliver the forgery.
        let verifier = verifier();
        cache_chain(&verifier, peer_chain(b"hi")).await;

        // The dispatch verifies, but the block is not applied, so record_seen is
        // not called (the ingest loop records only after an Applied outcome).
        let first = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        verifier
            .verify_block(&first, Slot::from(0))
            .await
            .expect("dispatch verifies");

        // A forged dispatch reusing the same key (same src zone, block, tx index)
        // with a different payload must still be re-derived and rejected, since
        // its key was never recorded as seen.
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

        let pass = consume_peer_stream(stream, PEER_ZONE, None, &peers, None).await;

        assert_eq!(pass.cursor, Some(Slot::from(1)));
        assert_eq!(pass.stalled_at, None);
        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(2));
    }

    #[tokio::test]
    async fn a_block_that_does_not_link_does_not_extend_the_verified_run() {
        let peers = PeerBlocks::default();
        let genesis = linked_chain(1);
        peers.insert(PEER_ZONE, genesis[0].clone()).await;
        // Claims the next id, but not the predecessor it would have to follow.
        peers
            .insert(
                PEER_ZONE,
                produce_dummy_block(GENESIS_BLOCK_ID + 1, None, vec![emission(b"hi")]),
            )
            .await;

        assert_eq!(
            peers.verified_prefix(PEER_ZONE).await,
            Some(GENESIS_BLOCK_ID)
        );
    }

    #[tokio::test]
    async fn a_block_arriving_between_the_two_halves_of_a_lookup_is_not_forged() {
        // `resolve` answers "cached?" and "inside the verified run?" under one
        // lock. Split across two, an insert landing between them reads as
        // absent-and-inside-the-run, the forgery signal, for a cached block.
        let peers = PeerBlocks::default();
        for block in linked_chain(2) {
            peers.insert(PEER_ZONE, block).await;
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
        // The tip is pinned at walk time, not re-derived from the blocks map:
        // re-derived, evicting the tip block (any future cache bounding) would
        // read as no tip at all, and the next honest block would misclassify as
        // NotTheGenesis and freeze the run for good.
        let peers = PeerBlocks::default();
        let chain = linked_chain(3);
        for block in chain.iter().take(2).cloned() {
            peers.insert(PEER_ZONE, block).await;
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
            peers.insert(PEER_ZONE, chain[2].clone()).await,
            "the next block still extends the run off the pinned tip"
        );
        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(3));
        // The evicted id keeps its classification: inside the run and absent.
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

        let pass = consume_peer_stream(stream, PEER_ZONE, None, &peers, None).await;

        assert_eq!(pass.cursor, Some(Slot::from(0)));
        assert_eq!(pass.stalled_at, Some(Slot::from(1)));
        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(1));
        assert!(peers.get(PEER_ZONE, 3).await.is_none());
    }

    #[tokio::test]
    async fn peer_reader_does_not_resume_inside_a_partially_failed_slot() {
        let peers = PeerBlocks::default();
        let chain = linked_chain(1);
        // One slot can carry several messages; the second one fails.
        let stream = stream::iter(vec![peer_block_msg(&chain[0], 7), undecodable_msg(7)]);

        let pass = consume_peer_stream(stream, PEER_ZONE, None, &peers, Some(Slot::from(6))).await;

        // Slot 7 is re-read whole next pass, not resumed past the failure.
        assert_eq!(pass.cursor, Some(Slot::from(6)));
    }

    #[tokio::test]
    async fn peer_reader_never_reads_past_a_slot_it_cannot_decode() {
        // It used to give up after DECODE_RETRY_LIMIT attempts and read on,
        // caching blocks the stalled run could never use. The watcher stops at
        // the same hole, so neither side delivers across it.
        let peers = PeerBlocks::default();
        let chain = linked_chain(3);
        let stream = stream::iter(vec![
            peer_block_msg(&chain[0], 0),
            undecodable_msg(1),
            peer_block_msg(&chain[2], 2),
        ]);

        let pass = consume_peer_stream(stream, PEER_ZONE, None, &peers, None).await;

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
        consume_peer_stream(stream, PEER_ZONE, None, &verifier.peers, None).await;

        // Regression: block 2 used to be reported as forged, halting ingestion
        // permanently, because a `max(cached ids)` high-water mark counted
        // blocks read past the undecodable slot. The reader now stops at that
        // slot, so block 2 is simply unread, which is lag.
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
        // The other half of #677. A peer inscribes a block claiming an id its
        // chain has not reached; it is well formed and correctly signed, so
        // nothing about the block itself refuses it. Delivered, its message
        // would burn the replay key the honest block at that id would later
        // need, and the inbox would no-op the real message.
        let verifier = verifier();
        cache_chain(&verifier, linked_chain(2)).await;
        let claimed = produce_dummy_block(9, None, vec![emission(b"hi")]);
        assert!(
            !verifier.peers.insert(PEER_ZONE, claimed).await,
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
        // A peer picks its own block ids, so one inscribed block claiming a huge
        // id would drive a `max(cached ids)` high-water mark past every real id
        // and make each later dispatch look forged. It is not the block that
        // would continue the run, so it is not cached at all.
        let verifier = verifier();
        let chain = linked_chain(2);
        verifier.peers.insert(PEER_ZONE, chain[0].clone()).await;
        verifier.peers.insert(PEER_ZONE, chain[1].clone()).await;
        verifier
            .peers
            .insert(
                PEER_ZONE,
                produce_dummy_block(u64::MAX, None, vec![emission(b"hi")]),
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
            None,
            &verifier.peers,
            None,
        )
        .await;
        assert_eq!(pass.cursor, None, "the failed slot is not skipped");
        assert_eq!(pass.stalled_at, Some(Slot::from(0)));

        // The next pass re-reads the same slot, which now decodes.
        let pass = consume_peer_stream(
            stream::iter(chain.iter().enumerate().map(|(index, block)| {
                peer_block_msg(block, u64::try_from(index).expect("test index fits in u64"))
            })),
            PEER_ZONE,
            None,
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

    /// The live brick from #648: a second, differing block at a used id replaced
    /// the entry, so the next dispatch naming that id re-derived against the
    /// wrong block and halted ingestion. One inscription, remote halt.
    #[tokio::test]
    async fn an_equivocating_peer_cannot_replace_a_cached_block() {
        let verifier = verifier();
        let mut chain = peer_chain(b"hi");
        let real = chain.pop().expect("chain has a last block");
        let impostor = produce_dummy_block(
            PEER_BLOCK_ID,
            Some(real.header.prev_block_hash),
            vec![emission(b"forged")],
        );
        assert_ne!(
            real.header.hash, impostor.header.hash,
            "the two blocks must differ, or this proves nothing"
        );

        cache_chain(&verifier, chain).await;
        assert!(verifier.peers.insert(PEER_ZONE, real.clone()).await);
        assert!(
            !verifier.peers.insert(PEER_ZONE, impostor).await,
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

        // And the dispatch that would have been rejected as forged still verifies.
        let block = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        verifier
            .verify_block(&block, Slot::from(0))
            .await
            .expect("equivocation must not halt ingestion of an honest dispatch");
    }

    #[tokio::test]
    async fn a_non_linking_block_at_the_run_head_does_not_lock_that_id_out() {
        // The other side of first-write-wins: refusing the honest block 3 when
        // it lands behind a claimed one would pin the run at 2 for the life of
        // the store, and every later message from that peer would stall.
        let peers = PeerBlocks::default();
        let chain = linked_chain(3);
        for block in chain.iter().take(2).cloned() {
            peers.insert(PEER_ZONE, block).await;
        }
        let claimed = produce_dummy_block(3, Some(HashType([9; 32])), vec![emission(b"claimed")]);
        assert!(peers.insert(PEER_ZONE, claimed).await);
        assert_eq!(
            peers.verified_prefix(PEER_ZONE).await,
            Some(2),
            "it cannot extend the run, which is what makes it inert but sticky"
        );

        let honest = chain[2].clone();
        assert!(
            peers.insert(PEER_ZONE, honest.clone()).await,
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
        // The two sides tie-break differently unless this reader stays strictly
        // sequential. The peer is its own sequencer, so it knows block 3's hash
        // before publishing it: it inscribes a block claiming id 4 and linking
        // to 3, then 3, then its honest 4.
        //
        // Caching ahead, the prefix would walk 3 and then straight through the
        // block held at 4, and the honest 4 would be refused when it landed.
        // The watcher reads in order, so at tip 2 it passes over the block
        // claiming 4 and never reconsiders it, then delivers from the honest 4.
        // Two different blocks at one id, and the dispatch naming it re-derives
        // against the wrong one and halts ingestion for good.
        let peers = PeerBlocks::default();
        let chain = linked_chain(4);
        for block in chain.iter().take(2).cloned() {
            peers.insert(PEER_ZONE, block).await;
        }
        let ahead = produce_dummy_block(4, Some(chain[2].header.hash), vec![emission(b"ahead")]);
        assert!(!peers.insert(PEER_ZONE, ahead).await);

        peers.insert(PEER_ZONE, chain[2].clone()).await;
        peers.insert(PEER_ZONE, chain[3].clone()).await;

        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(4));
        assert_eq!(
            peers.get(PEER_ZONE, 4).await.unwrap().header.hash,
            chain[3].header.hash,
            "the run holds the block the watcher delivered from"
        );
    }

    #[tokio::test]
    async fn a_block_below_the_peers_genesis_is_not_cached() {
        // It is on no chain the run can walk, so nothing would ever certify it,
        // and cached it would answer every later lookup at that id as though
        // the peer had built it.
        let peers = PeerBlocks::default();
        let below = produce_dummy_block(0, None, vec![emission(b"below")]);
        assert!(!peers.insert(PEER_ZONE, below).await);

        for block in linked_chain(3) {
            peers.insert(PEER_ZONE, block).await;
        }
        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(3));
        assert!(peers.get(PEER_ZONE, 0).await.is_none());
        // Under the run and unheld, which is the forgery signal, and the right
        // one: the peer's chain starts at its genesis, so only a dispatch that
        // invented the coordinate could name a block below it.
        assert!(matches!(
            peers.resolve(PEER_ZONE, 0).await,
            PeerLookup::InsideRun
        ));
    }

    #[tokio::test]
    async fn a_peer_whose_genesis_is_unread_resolves_to_behind() {
        // Before the run has a first block there is nothing to place anything
        // against, so every id is lag rather than forgery. Reading it the other
        // way round is the original hole: any inscribed block would resolve as
        // the peer's own, and any absent one as a forgery that halts.
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
        // #648 in the other direction: once the run has walked a block, a later
        // arrival at that id must not replace it, whatever it links to, or a
        // dispatch naming it re-derives against the new one and halts ingestion.
        let peers = PeerBlocks::default();
        let chain = linked_chain(2);
        for block in chain.iter().cloned() {
            peers.insert(PEER_ZONE, block).await;
        }
        assert_eq!(peers.verified_prefix(PEER_ZONE).await, Some(2));

        let impostor =
            produce_dummy_block(2, Some(chain[0].header.hash), vec![emission(b"forged")]);
        assert!(
            !peers.insert(PEER_ZONE, impostor).await,
            "it links to block 1 just as the held block does, and the run has certified the held one"
        );

        // The one that would slip through if displacement were allowed anywhere
        // below the id that extends the run: it links to the run's own head, so
        // every test but the id guard says take it.
        let plausible =
            produce_dummy_block(2, Some(chain[1].header.hash), vec![emission(b"forged")]);
        assert!(
            !peers.insert(PEER_ZONE, plausible).await,
            "displacement fires only at the id that would extend the run, never inside it"
        );
        assert_eq!(
            peers.get(PEER_ZONE, 2).await.unwrap().header.hash,
            chain[1].header.hash
        );
    }

    /// The reader re-reads a slot on every retry, so caching the same block
    /// twice must be a quiet no-op rather than equivocation.
    #[tokio::test]
    async fn re_reading_the_same_block_is_not_equivocation() {
        let verifier = verifier();
        let block = linked_chain(1).pop().expect("genesis block");

        assert!(verifier.peers.insert(PEER_ZONE, block.clone()).await);
        assert!(
            !verifier.peers.insert(PEER_ZONE, block.clone()).await,
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

    /// Recomputing `header.hash` on the way in is what stops a peer asserting
    /// links it never built.
    #[tokio::test]
    async fn a_block_whose_hash_does_not_match_its_contents_is_not_cached() {
        let verifier = verifier();
        let mut tampered = produce_dummy_block(PEER_BLOCK_ID, None, vec![emission(b"hi")]);
        tampered.header.hash = common::HashType([0xAB; 32]);

        let pass = consume_peer_stream(
            stream::iter(vec![peer_block_msg(&tampered, 0)]),
            PEER_ZONE,
            None,
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

    /// The watcher drops unsigned peer blocks before use; the reader applied no
    /// check at all, so anything on the channel entered the cache.
    #[tokio::test]
    async fn a_block_not_signed_by_the_pinned_key_is_not_cached() {
        let verifier = verifier();
        let block = linked_chain(1).pop().expect("genesis block");
        let wrong_key = PublicKey::try_new([42; 32]).unwrap();

        let pass = consume_peer_stream(
            stream::iter(vec![peer_block_msg(&block, 0)]),
            PEER_ZONE,
            Some(&wrong_key),
            &verifier.peers,
            None,
        )
        .await;

        assert_eq!(pass.stalled_at, None);
        assert!(
            verifier.peers.get(PEER_ZONE, PEER_BLOCK_ID).await.is_none(),
            "a block not signed by the pinned key must not reach the cache"
        );

        // The same block under its real signer is cached, so the gate is the key
        // and not the path.
        let signer = PublicKey::new_from_private_key(&PrivateKey::try_new([37; 32]).unwrap());
        consume_peer_stream(
            stream::iter(vec![peer_block_msg(&block, 1)]),
            PEER_ZONE,
            Some(&signer),
            &verifier.peers,
            None,
        )
        .await;
        assert!(
            verifier
                .peers
                .get(PEER_ZONE, GENESIS_BLOCK_ID)
                .await
                .is_some(),
            "the pinned signer's own block is cached"
        );
    }

    /// An at-tip pass over a peer verified to `verified_tip`, with the channel
    /// tip at `tip_slot` and the endpoint's LIB there too.
    fn at_tip_report(verified_tip: u64, tip_slot: u64) -> PassReport {
        at_tip_report_with_lib(verified_tip, tip_slot, Some(tip_slot))
    }

    /// [`at_tip_report`] with the endpoint's LIB pinned separately, to model a
    /// stale replica whose channel view drains below the real chain.
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
    async fn a_lagging_or_stalled_pass_resets_the_run() {
        let watch = PeerWatch::default();
        let start = Instant::now();

        watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
        // Drained, but behind the channel tip: says nothing about later blocks.
        watch.report_pass(
            PEER_ZONE,
            &PassReport {
                cursor_slot: Some(5),
                verified_tip: Some(2),
                stuck: None,
                drained: true,
                drained_at_tip: None,
                lib_slot: None,
            },
        );
        assert!(watch.confirmed_absence(PEER_ZONE, start, 0).is_none());

        watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
        // A stalled pass never reached the tip either.
        watch.report_pass(
            PEER_ZONE,
            &PassReport {
                cursor_slot: Some(6),
                verified_tip: Some(2),
                stuck: Some((7, 1)),
                drained: false,
                drained_at_tip: None,
                lib_slot: None,
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

        // The halting block was inscribed at slot 7, exactly the view's LIB:
        // the freshness bound holds at its boundary.
        let wait = verifier.wait_for_peer_block(PEER_ZONE, 9, 7);
        let keep_reporting = async {
            // One at-tip pass every 10s across the whole wait window.
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
        // The reader and this check share one Bedrock endpoint. A consistently
        // stale replica drains at its own channel tip, but its LIB sits below
        // the halting block's inscription slot, so its at-tip run says nothing
        // about a dispatch that block carries.
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
            // An undecodable slot breaks the run; the at-tip passes after it
            // start a new one that does not cover the wait.
            verifier.watch.report_pass(
                PEER_ZONE,
                &PassReport {
                    cursor_slot: Some(6),
                    verified_tip: Some(2),
                    stuck: Some((7, 1)),
                    drained: false,
                    drained_at_tip: None,
                    lib_slot: None,
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

    #[tokio::test(start_paused = true)]
    async fn evidence_from_a_reader_that_died_before_the_wait_does_not_escalate() {
        let verifier = verifier();
        cache_chain(&verifier, linked_chain(2)).await;
        verifier.watch.register(PEER_ZONE);
        verifier.watch.report_pass(PEER_ZONE, &at_tip_report(2, 7));
        tokio::time::sleep(Duration::from_secs(1)).await;

        // No passes at all during the wait: the reader may be dead, and a dead
        // reader proves nothing about the channel.
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
            },
        );
        watch.mark_halted([5; 32]);

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
            ],
            "registered-only, at-tip, stuck, drained-behind, halted"
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
        // No peer chain is cached at all, so nothing could verify. Recording
        // the keys is what the accept-list does, and the replay must then pass
        // exactly as a verified delivery's would.
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
}
