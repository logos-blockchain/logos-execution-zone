use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use anyhow::anyhow;
use common::{block::Block, transaction::LeeTransaction};
use cross_zone::{EmissionSource, build_dispatch_from_emission, extract_emission};
use cross_zone_inbox_core::{
    CrossZoneMessage, Instruction as InboxInstruction, MessageKey, ZoneId, message_key,
};
use futures::{Stream, StreamExt as _};
use lee::{GENESIS_BLOCK_ID, PublicKey};
use log::{debug, error, warn};
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use logos_blockchain_zone_sdk::{
    CommonHttpClient, Slot, ZoneMessage,
    adapter::NodeHttpClient,
    sequencer::{SequencerCheckpoint, ZoneSequencer},
};
use tokio::sync::RwLock;

use crate::config::IndexerConfig;

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

/// Consecutive passes a peer reader spends stuck on one slot before it says so
/// as something more than the per-pass failure. It never reads past the slot.
const STUCK_SLOT_ALERT_PASSES: u32 = 3;

/// Why a cross-zone dispatch could not be verified.
///
/// A forgery is terminal and must stop the block applying; an unavailable peer
/// block is transient and must be retried, or a lagging peer reader would
/// permanently halt ingestion.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CrossZoneVerifyError {
    /// The dispatch does not match the peer's finalized chain.
    #[error("{0:#}")]
    Forged(anyhow::Error),
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

/// The replay key plus the source block, which is what the inbox treats as one
/// delivery. Skipping re-derivation on the key alone would wave through a
/// dispatch the guest refuses, parking the block and holding ingestion.
type SeenKey = (MessageKey, [u8; 32]);

/// One peer zone's cached blocks, plus how far this reader has read them as an
/// unbroken hash-linked run from the peer's genesis.
#[derive(Default)]
struct PeerChain {
    blocks: HashMap<u64, Block>,
    /// Highest id such that every block from [`GENESIS_BLOCK_ID`] up to it has
    /// been read and each links to its predecessor. `None` until genesis is read.
    ///
    /// This, not `max(blocks.keys())`, is what the forgery test gates on: a peer
    /// picks its own `block_id`s, and an id that does not continue the run
    /// cannot advance the run.
    ///
    /// The link it walks means something only because [`accept_peer_block`]
    /// recomputes `header.hash` and checks the pinned key before anything is
    /// cached. Without that it compared two fields the peer wrote.
    verified_prefix: Option<u64>,
}

impl PeerChain {
    /// The id that would extend the verified run.
    const fn next_expected(&self) -> u64 {
        match self.verified_prefix {
            Some(prefix) => prefix.saturating_add(1),
            None => GENESIS_BLOCK_ID,
        }
    }

    /// Extends the verified run as far as the cached blocks allow.
    fn extend_prefix(&mut self) {
        while let Some(next) = self.blocks.get(&self.next_expected()) {
            let links = match self.verified_prefix {
                Some(prefix) => self
                    .blocks
                    .get(&prefix)
                    .is_some_and(|prev| prev.header.hash == next.header.prev_block_hash),
                // Genesis has no predecessor to link to.
                None => true,
            };
            if !links {
                return;
            }
            self.verified_prefix = Some(next.header.block_id);
        }
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
        let next = chain.next_expected();

        // Below the peer's genesis as well as ahead of the run: an id under
        // GENESIS_BLOCK_ID is on no chain the run can ever walk, and cached it
        // would resolve as the peer's own block for ever after.
        if block.header.block_id > next || block.header.block_id < GENESIS_BLOCK_ID {
            debug!(
                "Peer reader for {} not caching block {}: only block {next} continues the run verified from that peer's genesis.",
                hex::encode(zone),
                block.header.block_id
            );
            return false;
        }

        if let Some(held) = chain.blocks.get(&block.header.block_id) {
            if held.header.hash == block.header.hash {
                return false;
            }
            if block.header.block_id != next || !Self::extends_the_run(chain, &block) {
                error!(
                    "Peer zone {} equivocated at block {}: holding {}, refusing {}. Nothing at or above block {} can be delivered from until that peer inscribes a block continuing the run verified from its genesis.",
                    hex::encode(zone),
                    block.header.block_id,
                    held.header.hash,
                    block.header.hash,
                    block.header.block_id
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

    /// Whether `block` links to the block at the head of the verified run.
    ///
    /// False before the peer's genesis has been read, so the first block at that
    /// id wins and is never displaced, which is how the watcher anchors too.
    fn extends_the_run(chain: &PeerChain, block: &Block) -> bool {
        chain
            .verified_prefix
            .and_then(|prefix| chain.blocks.get(&prefix))
            .is_some_and(|tip| block.header.prev_block_hash == tip.header.hash)
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
        if chain.verified_prefix.is_none_or(|prefix| prefix < block_id) {
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
    #[cfg(test)]
    async fn verified_prefix(&self, zone: ZoneId) -> Option<u64> {
        self.chains
            .read()
            .await
            .get(&zone)
            .and_then(|chain| chain.verified_prefix)
    }
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
}

impl CrossZoneVerifier {
    /// Builds the verifier and spawns one peer reader per configured peer.
    /// Returns `None` when cross-zone messaging is disabled.
    pub fn start(config: &IndexerConfig) -> Option<Self> {
        let cross_zone = config.cross_zone.as_ref()?;
        let self_zone: ZoneId = *config.channel_id.as_ref();
        let peers = PeerBlocks::default();
        let mut peer_pubkeys = HashMap::new();

        for peer in &cross_zone.peers {
            let node = NodeHttpClient::new(
                CommonHttpClient::new(config.bedrock_config.auth.clone().map(Into::into)),
                config.bedrock_config.addr.clone(),
            );
            if let Some(bytes) = peer.expected_block_signing_pubkey {
                let pubkey = PublicKey::try_new(bytes)
                    .expect("configured peer block-signing pubkey is a valid key");
                peer_pubkeys.insert(peer.channel_id, pubkey);
            }
            tokio::spawn(read_peer(
                chain_state::consistency::new_indexer(ChannelId::from(peer.channel_id), node, None),
                peer.channel_id,
                peer_pubkeys.get(&peer.channel_id).cloned(),
                peers.clone(),
                config.consensus_info_polling_interval,
            ));
        }

        Some(Self {
            self_zone,
            peer_pubkeys,
            peers,
            seen: Arc::new(RwLock::new(HashSet::new())),
        })
    }

    /// Verifies every cross-zone dispatch in a block, returning the keys to mark
    /// seen, or the reason verification could not complete.
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
    pub async fn verify_block(&self, block: &Block) -> Result<Vec<SeenKey>, CrossZoneVerifyError> {
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

            let expected = self.rederive(&msg).await?;
            if LeeTransaction::Public(expected) != *tx {
                return Err(CrossZoneVerifyError::Forged(anyhow!(
                    "forged cross-zone dispatch from zone {} block {} tx {}: re-derivation mismatch",
                    hex::encode(msg.src_zone),
                    msg.src_block_id,
                    msg.src_tx_index
                )));
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
    ) -> Result<lee::PublicTransaction, CrossZoneVerifyError> {
        let peer_block = self
            .wait_for_peer_block(msg.src_zone, msg.src_block_id)
            .await?;

        // Equivocation defense: the source block must be signed by the peer's
        // pinned block-signing key, not merely inscribed on the channel.
        if let Some(expected) = self.peer_pubkeys.get(&msg.src_zone)
            && !peer_block.is_signed_by(expected)
        {
            return Err(CrossZoneVerifyError::Forged(anyhow!(
                "forged cross-zone dispatch: peer zone {} block {} is not signed by the pinned block-signing key",
                hex::encode(msg.src_zone),
                msg.src_block_id
            )));
        }

        // Everything below is a property of the peer block just read, so a
        // mismatch is the dispatch lying about it, not a transient condition.
        let emission_tx = peer_block
            .body
            .transactions
            .get(usize::try_from(msg.src_tx_index).expect("u32 index fits in usize"))
            .ok_or_else(|| {
                CrossZoneVerifyError::Forged(anyhow!(
                    "src_tx_index {} out of range in peer block",
                    msg.src_tx_index
                ))
            })?;

        let LeeTransaction::Public(emission_tx) = emission_tx else {
            return Err(CrossZoneVerifyError::Forged(anyhow!(
                "peer emission transaction is not public"
            )));
        };
        let message = emission_tx.message();
        let emission =
            extract_emission(message.program_id, &message.instruction_data).ok_or_else(|| {
                CrossZoneVerifyError::Forged(anyhow!(
                    "peer transaction at src_tx_index is not a recognized emitter"
                ))
            })?;

        if emission.target_zone != self.self_zone {
            return Err(CrossZoneVerifyError::Forged(anyhow!(
                "peer emission targets a different zone"
            )));
        }

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
    /// ingestion forever. A reference to a block the peer will never produce
    /// stalls rather than being rejected, since that is indistinguishable from a
    /// peer that has not produced it yet; either way it is never applied.
    async fn wait_for_peer_block(
        &self,
        zone: ZoneId,
        block_id: u64,
    ) -> Result<Block, CrossZoneVerifyError> {
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
                    return Err(CrossZoneVerifyError::Forged(anyhow!(
                        "forged cross-zone reference: peer zone {} chain is verified past block {} but it is absent",
                        hex::encode(zone),
                        block_id
                    )));
                }
                PeerLookup::Behind => {}
            }
            if waited >= PEER_BLOCK_WAIT_TIMEOUT {
                return Err(CrossZoneVerifyError::PeerUnavailable {
                    zone,
                    block_id,
                    waited,
                });
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

fn seen_key(msg: &CrossZoneMessage) -> SeenKey {
    (
        message_key(&msg.src_zone, msg.src_block_id, msg.src_tx_index),
        msg.src_block_hash,
    )
}

/// Whether a block read off a peer's channel may enter the cache. The channel
/// authorizes who may write, not what they may claim.
///
/// The hash check is unconditional: `header.hash` is a field the peer wrote and
/// the prefix walk compares it against the next block's `prev_block_hash`, so
/// without recomputing it a peer can assert links it never built. The key check
/// applies only when one is pinned, mirroring the watcher; it subsumes the hash
/// check, but a peer with no pinned key still gets that one.
fn accept_peer_block(
    block: &Block,
    peer_zone: ZoneId,
    expected_pubkey: Option<&PublicKey>,
) -> bool {
    if block.recompute_hash() != block.header.hash {
        warn!(
            "Peer reader dropping block {} from {}: header hash {} does not match its contents",
            block.header.block_id,
            hex::encode(peer_zone),
            block.header.hash
        );
        return false;
    }

    if let Some(expected) = expected_pubkey
        && !block.is_signed_by(expected)
    {
        warn!(
            "Peer reader dropping block {} from {}: not signed by the pinned block-signing key",
            block.header.block_id,
            hex::encode(peer_zone)
        );
        return false;
    }

    true
}

/// Reads a peer zone's finalized blocks from Bedrock into the shared cache.
#[expect(
    clippy::infinite_loop,
    reason = "the peer reader runs for the lifetime of the indexer process"
)]
async fn read_peer(
    mut zone_indexer: ZoneSequencer<NodeHttpClient>,
    peer_zone: ZoneId,
    expected_pubkey: Option<PublicKey>,
    peers: PeerBlocks,
    poll_interval: Duration,
) {
    log::info!(
        "Cross-zone peer reader started for {}",
        hex::encode(peer_zone)
    );
    let mut cursor = None;
    // The slot the reader is stuck on and how many passes it has spent there.
    // Keyed by slot so a failure at a new slot does not inherit an older slot's
    // count, and used only to say so once rather than every pass.
    let mut stalled: Option<(Slot, u32)> = None;
    loop {
        let stream = chain_state::consistency::next_messages(&mut zone_indexer).await;

        let pass =
            consume_peer_stream(stream, peer_zone, expected_pubkey.as_ref(), &peers, cursor).await;
        cursor = pass.cursor;
        if let Some(slot) = pass.stalled_at {
            let attempts = match stalled {
                Some((prev, attempts)) if prev == slot => attempts.saturating_add(1),
                _ => 1,
            };
            stalled = Some((slot, attempts));
            // Every threshold rather than on the crossing alone: a stall
            // that never clears would otherwise be reported once and
            // then look resolved for as long as it lasts.
            if attempts > 0 && attempts.is_multiple_of(STUCK_SLOT_ALERT_PASSES) {
                error!(
                    "Peer reader for {} has been stuck at slot {slot:?} for {attempts} passes. The run verified from that peer's genesis stops below it, so every dispatch naming a later block stalls until this slot can be read.",
                    hex::encode(peer_zone)
                );
            }
        } else {
            stalled = None;
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
    S: Stream<Item = (ZoneMessage, SequencerCheckpoint)>,
{
    let mut stream = std::pin::pin!(stream);
    let mut cursor = resume_from;
    // The slot being consumed: cached so far, but there may be more to come.
    let mut in_progress: Option<Slot> = None;

    while let Some((
        msg,
        SequencerCheckpoint {
            last_msg_id: _,
            pending_txs: _,
            lib: _,
            lib_slot: slot,
        },
    )) = stream.next().await
    {
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
    use futures::stream;
    use lee::{
        PrivateKey, PublicKey, PublicTransaction,
        public_transaction::{Message, WitnessSet},
    };
    use logos_blockchain_core::mantle::ops::channel::{MsgId, inscribe::Inscription};
    use logos_blockchain_zone_sdk::ZoneBlock;
    use ping_core::{SenderInstruction, ping_record_pda, receiver_config_account_id};

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
        }
    }

    /// A `ping_sender` emission addressed to `SELF_ZONE` carrying `payload`.
    fn emission(payload: &[u8]) -> LeeTransaction {
        let receiver_id = programs::ping_receiver().id();
        let send = SenderInstruction::Send {
            target_zone: SELF_ZONE,
            target_program_id: receiver_id,
            target_accounts: vec![
                receiver_config_account_id(receiver_id).into_value(),
                ping_record_pda(receiver_id).into_value(),
            ],
            payload: payload.to_vec(),
            ordinal: 0,
        };
        let message = Message::try_new(programs::ping_sender().id(), vec![], vec![], send)
            .expect("emission serializes");
        LeeTransaction::Public(PublicTransaction::new(
            message,
            WitnessSet::from_raw_parts(vec![]),
        ))
    }

    /// A peer-stream item inscribing `data` at `slot`.
    fn peer_msg(data: Vec<u8>, slot: u64) -> (ZoneMessage, SequencerCheckpoint) {
        (
            ZoneMessage::Block(ZoneBlock {
                id: MsgId::from([0; 32]),
                data: Inscription::try_from(data).expect("test inscription is within bounds"),
            }),
            SequencerCheckpoint {
                last_msg_id: MsgId::from([0_u8; 32]),
                pending_txs: vec![],
                lib: [1_u8; 32].into(),
                lib_slot: Slot::new(slot),
            },
        )
    }

    /// A hash-linked chain of `len` blocks from genesis, each carrying a `b"hi"`
    /// emission. Only a chain built this way advances the verified prefix.
    fn linked_chain(len: u64) -> Vec<Block> {
        let mut prev = None;
        let mut blocks = Vec::new();
        for offset in 0..len {
            let block = produce_dummy_block(
                GENESIS_BLOCK_ID.saturating_add(offset),
                prev,
                vec![emission(b"hi")],
            );
            prev = Some(block.header.hash);
            blocks.push(block);
        }
        blocks
    }

    /// A peer-stream item carrying `block`.
    fn peer_block_msg(block: &Block, slot: u64) -> (ZoneMessage, SequencerCheckpoint) {
        peer_msg(borsh::to_vec(block).expect("block serializes"), slot)
    }

    /// A hash-linked run from the peer's genesis whose last block,
    /// `PEER_BLOCK_ID`, carries a `payload` emission. The run is what makes that
    /// block deliverable.
    fn peer_chain(payload: &[u8]) -> Vec<Block> {
        let mut chain = linked_chain(PEER_BLOCK_ID.saturating_sub(GENESIS_BLOCK_ID));
        let prev = chain.last().map(|block| block.header.hash);
        chain.push(produce_dummy_block(
            PEER_BLOCK_ID,
            prev,
            vec![emission(payload)],
        ));
        chain
    }

    /// Caches a run so its last block sits inside the verified prefix.
    async fn cache_chain(verifier: &CrossZoneVerifier, chain: Vec<Block>) {
        for block in chain {
            verifier.peers.insert(PEER_ZONE, block).await;
        }
    }

    /// A peer-stream item whose inscription is not a decodable block.
    fn undecodable_msg(slot: u64) -> (ZoneMessage, SequencerCheckpoint) {
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
            .verify_block(&block)
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
                verifier.verify_block(&block).await,
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
        let err = verifier.verify_block(&block).await.unwrap_err();
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
            .verify_block(&block)
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
        let err = verifier.verify_block(&block).await.unwrap_err();
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
            .verify_block(&first)
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
            .verify_block(&replay)
            .await
            .expect("a replay is accepted as an on-chain no-op");
    }

    #[tokio::test]
    async fn a_seen_coordinate_does_not_excuse_a_different_source_block() {
        let verifier = verifier();
        cache_chain(&verifier, peer_chain(b"hi")).await;

        let first = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        let keys = verifier.verify_block(&first).await.expect("first verifies");
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
                verifier.verify_block(&other).await,
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
            .verify_block(&first)
            .await
            .expect("dispatch verifies");

        // A forged dispatch reusing the same key (same src zone, block, tx index)
        // with a different payload must still be re-derived and rejected, since
        // its key was never recorded as seen.
        let forged = produce_dummy_block(10, None, vec![dispatch(b"forged")]);
        let err = verifier.verify_block(&forged).await.unwrap_err();
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
            .wait_for_peer_block(PEER_ZONE, 2)
            .await
            .expect_err("block 2 was never read, so it cannot be resolved");
        assert!(
            matches!(err, CrossZoneVerifyError::PeerUnavailable { .. }),
            "a block outside the verified run is lag, not forgery: {err}"
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
            .wait_for_peer_block(PEER_ZONE, 9)
            .await
            .expect_err("a block off the verified run must not resolve");
        assert!(
            matches!(err, CrossZoneVerifyError::PeerUnavailable { .. }),
            "a claimed id and a reader that is behind read alike, so this stalls rather than halting: {err}"
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
            .wait_for_peer_block(PEER_ZONE, 3)
            .await
            .expect_err("block 3 has not been read yet");
        assert!(
            matches!(err, CrossZoneVerifyError::PeerUnavailable { .. }),
            "a block beyond the verified run is lag, not forgery: {err}"
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
            .verify_block(&block)
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
            .verify_block(&block)
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
}
