use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use anyhow::anyhow;
use common::{block::Block, transaction::LeeTransaction};
use cross_zone::{build_dispatch_from_emission, extract_emission};
use cross_zone_inbox_core::{
    CrossZoneMessage, Instruction as InboxInstruction, MessageKey, ZoneId, message_key,
};
use futures::{Stream, StreamExt as _};
use lee::{GENESIS_BLOCK_ID, PublicKey};
use log::{debug, error, info, warn};
use logos_blockchain_core::mantle::ops::channel::ChannelId;
use logos_blockchain_zone_sdk::{
    CommonHttpClient, Slot, ZoneMessage, adapter::NodeHttpClient, indexer::ZoneIndexer,
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

/// Consecutive passes a peer reader re-reads the same undecodable slot before
/// giving up and reading past it.
const DECODE_RETRY_LIMIT: u32 = 3;

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
    /// Caches `block` unless a different block is already held at its id, and
    /// says whether it was newly cached.
    ///
    /// First write wins. An identical re-read is a no-op, which the reader does
    /// on every slot retry. A differing block at a held id is equivocation, and
    /// replacing the entry is what makes it a remote halt: the prefix already
    /// certified the old value, so the next dispatch naming that id re-derives
    /// against the new one and reads as forged.
    ///
    /// A peer resetting its chain is indistinguishable from this and is refused
    /// the same way. The cache is process-local, so a restart adopts it.
    async fn insert(&self, zone: ZoneId, block: Block) -> bool {
        let mut chains = self.chains.write().await;
        let chain = chains.entry(zone).or_default();

        if let Some(held) = chain.blocks.get(&block.header.block_id) {
            if held.header.hash == block.header.hash {
                return false;
            }
            error!(
                "Peer zone {} equivocated at block {}: holding {}, refusing {}. Restart the indexer if this peer legitimately reset its chain.",
                hex::encode(zone),
                block.header.block_id,
                held.header.hash,
                block.header.hash
            );
            return false;
        }

        chain.blocks.insert(block.header.block_id, block);
        chain.extend_prefix();
        true
    }

    /// Resolves `block_id` under a single read lock.
    ///
    /// Answering "is it cached?" and "is it inside the verified run?" under two
    /// separate locks races with the peer reader: an insert landing between them
    /// reads as absent-and-inside-the-run, which is the forgery signal, for a
    /// block that is in fact cached. That is the normal steady state, a waiting
    /// verifier and the block it waits for arriving, so it must be one look.
    async fn resolve(&self, zone: ZoneId, block_id: u64) -> PeerLookup {
        let chains = self.chains.read().await;
        let Some(chain) = chains.get(&zone) else {
            return PeerLookup::Behind;
        };
        if let Some(block) = chain.blocks.get(&block_id) {
            return PeerLookup::Cached(Box::new(block.clone()));
        }
        if chain
            .verified_prefix
            .is_some_and(|prefix| prefix >= block_id)
        {
            PeerLookup::InsideRun
        } else {
            PeerLookup::Behind
        }
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
    seen: Arc<RwLock<HashSet<MessageKey>>>,
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
                ZoneIndexer::new(ChannelId::from(peer.channel_id), node),
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
    pub async fn verify_block(
        &self,
        block: &Block,
    ) -> Result<Vec<MessageKey>, CrossZoneVerifyError> {
        let mut verified = Vec::new();
        for tx in &block.body.transactions {
            let Some(msg) = Self::decode_dispatch(tx) else {
                continue;
            };

            let key = message_key(&msg.src_zone, msg.src_block_id, msg.src_tx_index);
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

            info!(
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
    pub async fn record_seen(&self, keys: Vec<MessageKey>) {
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

        Ok(build_dispatch_from_emission(
            msg.src_zone,
            msg.src_block_id,
            msg.src_tx_index,
            message.program_id,
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
                info!(
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
    zone_indexer: ZoneIndexer<NodeHttpClient>,
    peer_zone: ZoneId,
    expected_pubkey: Option<PublicKey>,
    peers: PeerBlocks,
    poll_interval: Duration,
) {
    info!(
        "Cross-zone peer reader started for {}",
        hex::encode(peer_zone)
    );

    let mut cursor = None;
    // The slot the reader is stuck on and how many passes it has spent there.
    // Keyed by slot: the retry budget is per slot, so a failure at a new slot
    // must not inherit an older slot's count and be skipped on its first try.
    let mut stalled: Option<(Slot, u32)> = None;
    let mut skip_slot = None;
    loop {
        match zone_indexer.next_messages(cursor).await {
            Ok(stream) => {
                let pass = consume_peer_stream(
                    stream,
                    peer_zone,
                    expected_pubkey.as_ref(),
                    &peers,
                    cursor,
                    skip_slot,
                )
                .await;
                cursor = pass.cursor;
                if let Some(slot) = pass.stalled_at {
                    let attempts = match stalled {
                        Some((prev, attempts)) if prev == slot => attempts.saturating_add(1),
                        _ => 1,
                    };
                    if attempts >= DECODE_RETRY_LIMIT {
                        // Reading on leaves a hole: dispatches referencing the
                        // skipped block can no longer be verified, but every
                        // later block stays readable.
                        error!(
                            "Peer reader for {} could not decode slot {slot:?} after {attempts} attempts; reading past it.",
                            hex::encode(peer_zone)
                        );
                        skip_slot = Some(slot);
                        stalled = None;
                    } else {
                        stalled = Some((slot, attempts));
                    }
                } else {
                    stalled = None;
                    skip_slot = None;
                }
            }
            Err(err) => error!(
                "Peer reader next_messages failed for {}: {err}",
                hex::encode(peer_zone)
            ),
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Caches the finalized peer blocks carried by `stream`.
///
/// A block that fails to deserialize ends the pass and holds the cursor at the
/// last fully-consumed slot, so the next poll re-reads it and a transient
/// failure heals itself. `skip_slot` names a slot the caller gave up on after
/// [`DECODE_RETRY_LIMIT`] attempts, which is read past instead so a permanently
/// undecodable inscription cannot wedge the reader. Skipping only leaves a hole,
/// which cannot advance [`PeerChain::verified_prefix`] past itself.
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
    skip_slot: Option<Slot>,
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
            Err(err) if skip_slot == Some(slot) => {
                debug!(
                    "Peer reader skipping undecodable block from {} at slot {slot:?}: {err}",
                    hex::encode(peer_zone)
                );
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
    use common::test_utils::produce_dummy_block;
    use futures::stream;
    use lee::{
        PrivateKey, PublicKey, PublicTransaction,
        public_transaction::{Message, WitnessSet},
    };
    use logos_blockchain_core::mantle::ops::channel::{MsgId, inscribe::Inscription};
    use logos_blockchain_zone_sdk::ZoneBlock;
    use ping_core::{SenderInstruction, ping_record_pda};

    use super::*;

    const SELF_ZONE: ZoneId = [1; 32];
    const PEER_ZONE: ZoneId = [2; 32];
    const PEER_BLOCK_ID: u64 = 5;

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
            outbox_program_id: programs::cross_zone_outbox().id(),
            target_zone: SELF_ZONE,
            target_program_id: receiver_id,
            target_accounts: vec![ping_record_pda(receiver_id).into_value()],
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
    fn peer_block_msg(block: &Block, slot: u64) -> (ZoneMessage, Slot) {
        peer_msg(borsh::to_vec(block).expect("block serializes"), slot)
    }

    /// A peer-stream item whose inscription is not a decodable block.
    fn undecodable_msg(slot: u64) -> (ZoneMessage, Slot) {
        peer_msg(b"not a block".to_vec(), slot)
    }

    /// The dispatch a watcher would inject for a `PEER_BLOCK_ID` emission of `payload`.
    fn dispatch(payload: &[u8]) -> LeeTransaction {
        let receiver_id = programs::ping_receiver().id();
        LeeTransaction::Public(build_dispatch_from_emission(
            PEER_ZONE,
            PEER_BLOCK_ID,
            0,
            programs::ping_sender().id(),
            receiver_id,
            &[ping_record_pda(receiver_id).into_value()],
            payload.to_vec(),
        ))
    }

    #[tokio::test]
    async fn verifies_dispatch_matching_a_peer_emission() {
        let verifier = verifier();
        verifier
            .peers
            .insert(
                PEER_ZONE,
                produce_dummy_block(PEER_BLOCK_ID, None, vec![emission(b"hi")]),
            )
            .await;

        let block = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        verifier
            .verify_block(&block)
            .await
            .expect("dispatch matching the peer emission verifies");
    }

    #[tokio::test]
    async fn rejects_dispatch_with_no_matching_emission() {
        let verifier = verifier();
        // The peer block carries the real emission, but the block claims a
        // different payload, so re-derivation does not reproduce it.
        verifier
            .peers
            .insert(
                PEER_ZONE,
                produce_dummy_block(PEER_BLOCK_ID, None, vec![emission(b"real")]),
            )
            .await;

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
        verifier
            .peers
            .insert(
                PEER_ZONE,
                produce_dummy_block(PEER_BLOCK_ID, None, vec![emission(b"hi")]),
            )
            .await;

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
        verifier
            .peers
            .insert(
                PEER_ZONE,
                produce_dummy_block(PEER_BLOCK_ID, None, vec![emission(b"hi")]),
            )
            .await;

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
        verifier
            .peers
            .insert(
                PEER_ZONE,
                produce_dummy_block(PEER_BLOCK_ID, None, vec![emission(b"hi")]),
            )
            .await;

        let first = produce_dummy_block(9, None, vec![dispatch(b"hi")]);
        let keys = verifier
            .verify_block(&first)
            .await
            .expect("first delivery verifies");
        // Mark the delivery seen, as the ingest loop does once the block applies.
        verifier.record_seen(keys).await;

        // Replace the peer block with a different emission so re-deriving the
        // replay would mismatch. The replay must still be accepted, proving it is
        // the seen-key short-circuit (the inbox no-ops it on chain) and not a
        // successful re-derivation.
        verifier
            .peers
            .insert(
                PEER_ZONE,
                produce_dummy_block(PEER_BLOCK_ID, None, vec![emission(b"different")]),
            )
            .await;

        let replay = produce_dummy_block(10, None, vec![dispatch(b"hi")]);
        verifier
            .verify_block(&replay)
            .await
            .expect("a replay is accepted as an on-chain no-op");
    }

    #[tokio::test]
    async fn unaccepted_dispatch_does_not_poison_seen() {
        // A dispatch verified in a block that never applies (e.g. one that parks)
        // must not be marked seen. Otherwise a later forged dispatch could reuse
        // its key to skip re-derivation, while the inbox, never having recorded
        // the key on chain, would deliver the forgery.
        let verifier = verifier();
        verifier
            .peers
            .insert(
                PEER_ZONE,
                produce_dummy_block(PEER_BLOCK_ID, None, vec![emission(b"hi")]),
            )
            .await;

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

        let pass = consume_peer_stream(stream, PEER_ZONE, None, &peers, None, None).await;

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

        let pass = consume_peer_stream(stream, PEER_ZONE, None, &peers, None, None).await;

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

        let pass =
            consume_peer_stream(stream, PEER_ZONE, None, &peers, Some(Slot::from(6)), None).await;

        // Slot 7 is re-read whole next pass, not resumed past the failure.
        assert_eq!(pass.cursor, Some(Slot::from(6)));
    }

    #[tokio::test]
    async fn peer_reader_reads_past_a_slot_it_has_given_up_on() {
        // After DECODE_RETRY_LIMIT attempts the caller nominates the slot to
        // skip, so a permanently undecodable inscription cannot wedge the reader.
        let peers = PeerBlocks::default();
        let chain = linked_chain(3);
        let stream = stream::iter(vec![
            peer_block_msg(&chain[0], 0),
            undecodable_msg(1),
            peer_block_msg(&chain[2], 2),
        ]);

        let pass =
            consume_peer_stream(stream, PEER_ZONE, None, &peers, None, Some(Slot::from(1))).await;

        assert_eq!(pass.cursor, Some(Slot::from(2)), "the pass drains");
        assert_eq!(pass.stalled_at, None);
        // Block 3 is cached and servable, so dispatches referencing it verify.
        assert!(peers.get(PEER_ZONE, 3).await.is_some());
        // But the hole stops the verified run, so block 2 is never called forged.
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
        consume_peer_stream(
            stream,
            PEER_ZONE,
            None,
            &verifier.peers,
            None,
            Some(Slot::from(1)),
        )
        .await;

        // Regression: the reader cached block 3, so the old `max(cached ids)`
        // high-water mark reached 3 and a dispatch referencing block 2 was
        // rejected as forged, halting ingestion permanently.
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
    async fn a_high_block_id_cannot_poison_the_forgery_test() {
        // A peer picks its own block ids, so one inscribed block claiming a huge
        // id would drive a `max(cached ids)` high-water mark past every real id
        // and make each later dispatch look forged. It cannot extend the
        // verified run, so it is inert.
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
            None,
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
        let real = produce_dummy_block(PEER_BLOCK_ID, None, vec![emission(b"hi")]);
        let impostor = produce_dummy_block(PEER_BLOCK_ID, None, vec![emission(b"forged")]);
        assert_ne!(
            real.header.hash, impostor.header.hash,
            "the two blocks must differ, or this proves nothing"
        );

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

    /// The reader re-reads a slot on every retry, so caching the same block
    /// twice must be a quiet no-op rather than equivocation.
    #[tokio::test]
    async fn re_reading_the_same_block_is_not_equivocation() {
        let verifier = verifier();
        let block = produce_dummy_block(PEER_BLOCK_ID, None, vec![emission(b"hi")]);

        assert!(verifier.peers.insert(PEER_ZONE, block.clone()).await);
        assert!(
            !verifier.peers.insert(PEER_ZONE, block.clone()).await,
            "an identical re-read is already held, not newly cached"
        );
        assert_eq!(
            verifier
                .peers
                .get(PEER_ZONE, PEER_BLOCK_ID)
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
        let block = produce_dummy_block(PEER_BLOCK_ID, None, vec![emission(b"hi")]);
        let wrong_key = PublicKey::try_new([42; 32]).unwrap();

        let pass = consume_peer_stream(
            stream::iter(vec![peer_block_msg(&block, 0)]),
            PEER_ZONE,
            Some(&wrong_key),
            &verifier.peers,
            None,
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
            None,
        )
        .await;
        assert!(
            verifier.peers.get(PEER_ZONE, PEER_BLOCK_ID).await.is_some(),
            "the pinned signer's own block is cached"
        );
    }
}
