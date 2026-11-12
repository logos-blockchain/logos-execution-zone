use std::{collections::VecDeque, path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use arc_swap::ArcSwap;
use chain_state::{
    Anchor, ChainConsistency, ChainState, ChannelEntry, ProofStore, Tip, Verdict,
    chain::SettledBlock, zone_indexer::ZoneIndexer,
};
pub use chain_state::{BlockIngestError, StallReason, timeout_node::TimeoutNode};
use common::block::{Block, DigestedBlock};
// TODO: Remove after testnet
use futures::StreamExt as _;
use lee::privacy_preserving_transaction::circuit::ProofDigest;
use log::{error, warn};
use logos_blockchain_core::mantle::ops::channel::MsgId;
use logos_blockchain_zone_sdk::{CommonHttpClient, Slot, ZoneMessage, adapter::NodeHttpClient};
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};

use crate::{
    block_store::{IndexerStore, PutSettledError, Stored},
    config::IndexerConfig,
    cross_zone_verifier::{CrossZoneVerifier, CrossZoneVerifyError, ForgedDispatch, SeenKey},
    status::{CrossZoneHalt, IndexerStatus, IndexerSyncStatus},
};

pub mod block_store;
pub mod config;
pub mod cross_zone_verifier;
pub mod event_filter;
pub mod status;

/// Bytes of fetched proofs kept once no block the fold holds pins them.
const PROOF_STORE_CAPACITY: usize = 256 * 1024 * 1024;

/// How ingestion goes on once the settled blocks are handed to the store.
enum Step {
    Done,
    /// A block is held for a retry next pass.
    Held,
    /// A forged dispatch halted ingestion.
    Halted,
}

/// The fold over the channel and what the ingest loop carries between passes.
struct Ingest {
    chain: ChainState,
    /// The last slot whose messages are all folded.
    read: Option<Slot>,
    /// The last message folded, which the next one chains on.
    parent: MsgId,
    /// The stored message a restart resumes after, until it is re-read.
    resume: Option<(MsgId, Slot)>,
    /// Settled blocks not yet stored, in order.
    settled: VecDeque<SettledBlock>,
    /// The proofs no source served this pass, not asked for again until the next.
    unserved: Vec<ProofDigest>,
    /// In-memory mirror of the persisted halt record, so clearing it when the
    /// recorded block later applies needs no per-block read.
    pending_halt: Option<CrossZoneHalt>,
}

#[derive(Clone)]
pub struct IndexerCore {
    pub zone_indexer: Arc<ZoneIndexer<TimeoutNode<NodeHttpClient>>>,
    /// Direct node handle for queries outside `ZoneIndexer`'s streaming API.
    pub node: TimeoutNode<NodeHttpClient>,
    pub config: IndexerConfig,
    pub store: IndexerStore,
    /// Live ingestion status; updated by the ingest stream, read by `status`.
    pub status: Arc<ArcSwap<IndexerSyncStatus>>,
    /// Option B cross-zone verifier; `None` when cross-zone messaging is disabled.
    pub verifier: Option<CrossZoneVerifier>,
    pub proof_sources: Vec<SequencerClient>,
    /// The proofs the fold hydrates blocks with, fetched from `proof_sources`.
    pub proofs: ProofStore,
}

impl Ingest {
    /// Whether `msg`, read at `slot`, is a re-read of what the store already holds.
    fn re_read(&mut self, msg: MsgId, slot: Slot) -> bool {
        let Some((stored, at)) = self.resume else {
            return false;
        };
        if slot > at {
            warn!(
                "The channel did not serve message {stored} again at slot {at:?}, the last one \
                 whose block is stored; folding on from slot {slot:?}"
            );
            self.resume = None;
            return false;
        }
        if msg == stored {
            self.resume = None;
        }
        true
    }

    /// Folds the finalized `entries` with the L1 LIB at `lib`, and queues the
    /// blocks that settle. Every finalized entry up to `lib` must be folded by then.
    fn fold(&mut self, entries: &[ChannelEntry], lib: Slot) {
        if let Some(last) = entries.last() {
            self.parent = last.msg;
        }
        let folded = self.chain.apply_finalized(entries, lib);
        for outcome in &folded.judged {
            let block_id = outcome.block.header.block_id;
            match &outcome.verdict {
                Verdict::Settled | Verdict::AlreadySettled(_) => {}
                Verdict::Dropped { error, .. } => error!("Dropped block {block_id}: {error}"),
                Verdict::Cut => error!(
                    "Block {block_id} left the branch: cut by a skip, or with a dead ancestor"
                ),
                Verdict::LateSkip => error!("Ignored block {block_id}: a skip after its window"),
                Verdict::Ignored => error!("Ignored block {block_id}: its parent is not known"),
            }
        }
        self.settled.extend(folded.settled);
    }
}

impl IndexerCore {
    /// Builds the core, then verifies the stored chain matches the channel's by
    /// re-reading the channel at the stored tip's position.
    ///
    /// On mismatch: refuse (error) unless `config.allow_chain_reset` is set, in which case wipe the
    /// store and re-index from scratch.
    pub async fn new(config: IndexerConfig, storage_dir: &Path) -> Result<Self> {
        let home = storage_dir.join(format!("rocksdb-{}", config.channel_id));
        let core = Self::open(config.clone(), storage_dir)?;
        match core.verify_chain_consistency().await? {
            // `Inconclusive` is deliberately treated the same as `Consistent`.
            //
            // We could not prove a reset, so proceed from the cursor without wiping
            // a possibly-valid store. A genuinely divergent chain is still caught
            // later when the ingest loop tries to apply and parks.
            ChainConsistency::Consistent | ChainConsistency::Inconclusive => Ok(core),
            ChainConsistency::Inconsistent(mismatch) if config.allow_chain_reset => {
                warn!(
                    "Chain reset detected ({mismatch}). Wiping indexer store at {} and \
                     re-indexing.",
                    home.display()
                );
                drop(core); // sole owner before the ingest task is spawned → closes the DB
                storage::indexer::RocksDBIO::destroy(&home)?;
                Self::open(config, storage_dir)
            }
            ChainConsistency::Inconsistent(mismatch) => Err(anyhow::anyhow!(
                "Indexer store at {} holds a different chain than the channel now serves \
                 ({mismatch}). Delete the indexer storage directory, point at a fresh one, or \
                 set `allow_chain_reset` in the indexer config.",
                home.display()
            )),
        }
    }

    /// Opens the store and builds the core without the chain-identity check.
    fn open(config: IndexerConfig, storage_dir: &Path) -> Result<Self> {
        // Namespace the DB by channel so indexers on different channels can
        // share a storage dir without their RocksDB state colliding.
        let home = storage_dir.join(format!("rocksdb-{}", config.channel_id));

        let basic_auth = config.bedrock_config.auth.clone().map(Into::into);
        let node = TimeoutNode::new(NodeHttpClient::new(
            CommonHttpClient::new(basic_auth),
            config.bedrock_config.addr.clone(),
        ));
        let zone_indexer = ZoneIndexer::new(config.channel_id, node.clone());

        let proof_sources = config
            .proof_sources
            .iter()
            .map(|source| {
                let mut builder = SequencerClientBuilder::default();
                if let Some(auth) = &source.auth {
                    builder = builder.set_headers(
                        std::iter::once((
                            "Authorization".parse().expect("Header name is valid"),
                            format!("Basic {auth}")
                                .parse()
                                .context("Invalid basic auth format")?,
                        ))
                        .collect(),
                    );
                }
                builder
                    .build(&source.addr)
                    .context("Failed to create proof source client")
            })
            .collect::<Result<Vec<_>>>()?;

        // Option B verifier: re-derives each cross-zone dispatch from the peer's
        // finalized blocks. `None` when cross-zone messaging is disabled.
        let verifier = CrossZoneVerifier::start(&config);

        let store = IndexerStore::open_db(
            &home,
            config.cross_zone.is_some(),
            Vec::new(),
            config.event_filter.to_filter()?,
        )?;
        // A persisted halt outlives the process: report it from boot with its
        // stored reason. The ingest loop may still start and re-halt
        // identically, which refreshes the record.
        let initial_status = match store.get_cross_zone_halt() {
            Ok(Some(halt)) => IndexerSyncStatus::halted(halt.to_string()),
            Ok(None) => IndexerSyncStatus::starting(),
            Err(err) => {
                warn!("Failed to read cross-zone halt record at startup: {err:#}");
                IndexerSyncStatus::starting()
            }
        };

        Ok(Self {
            zone_indexer: Arc::new(zone_indexer),
            store,
            node,
            config,
            status: Arc::new(ArcSwap::from_pointee(initial_status)),
            verifier,
            proof_sources,
            proofs: ProofStore::new(PROOF_STORE_CAPACITY),
        })
    }

    /// Verifies whether the channel still serves the same chain the store was built from.
    /// This may change frequently during development where we reset the chain from time to
    /// time in devnet/testnet, but we do not expect [`ChainConsistency::Inconsistent`] in
    /// production.
    ///
    /// To compare the chains, we use an [`Anchor`] block that is either the parked L2 block
    /// while stalled, or the tip L2 block at its own inscription L1 slot.
    pub(crate) async fn verify_chain_consistency(&self) -> Result<ChainConsistency> {
        let Some(anchor) = self.get_startup_anchor()? else {
            // empty or cold store: nothing to compare
            return Ok(ChainConsistency::Inconclusive);
        };

        chain_state::verify_chain_consistency(&self.node, self.config.channel_id, &anchor).await
    }

    /// Builds the anchor for the startup check.
    ///
    /// - If stalled, returns the recorded _parked_ block
    /// - If not stalled, returns the validated tip at its _own_ inscription slot.
    /// - If the store is empty, returns `None`.
    fn get_startup_anchor(&self) -> Result<Option<Anchor>> {
        if let Some(stall) = self.store.get_stall_reason()? {
            return Ok(Some(Anchor::new(
                stall.l1_slot,
                stall.block_id.zip(stall.block_hash),
            )));
        }

        // not stalled, so anchor on the tip at its own inscription slot
        let Some(slot) = self.store.get_tip_slot()?.map_or_else(
            || anyhow::Ok(self.store.get_zone_cursor()?.map(|(_, slot)| slot)),
            |slot| Ok(Some(slot)),
        )?
        else {
            return Ok(None);
        };
        let Some(tip_id) = self.store.get_last_block_id()? else {
            return Ok(None);
        };
        let Some(tip) = self.store.get_block_at_id(tip_id)? else {
            return Ok(None);
        };
        Ok(Some(Anchor::new(slot, Some((tip_id, tip.header.hash)))))
    }

    /// Snapshot of the current ingestion status (sync state + indexed tip).
    ///
    /// Combines the ingest loop's live status with the L2 tip read fresh from the
    /// store, so callers (FFI/RPC) can tell "catching up" from "failed".
    #[must_use]
    pub fn status(&self) -> IndexerStatus {
        let sync = IndexerSyncStatus::clone(&self.status.load());
        // Log-and-fall-back rather than collapsing a store error into the same
        // `None` as "legitimately absent": a DB read failure must not silently
        // masquerade as "no tip yet" / "no stall recorded" in the snapshot.
        let indexed_block_id = match self.store.get_last_block_id() {
            Ok(id) => id,
            Err(err) => {
                warn!("Failed to read last indexed block id for status: {err:#}");
                None
            }
        };
        let stall_reason = match self.store.get_stall_reason() {
            Ok(reason) => reason,
            Err(err) => {
                warn!("Failed to read stall reason for status: {err:#}");
                None
            }
        };
        let cross_zone_halt = match self.store.get_cross_zone_halt() {
            Ok(halt) => halt,
            Err(err) => {
                warn!("Failed to read cross-zone halt record for status: {err:#}");
                None
            }
        };
        IndexerStatus {
            sync,
            indexed_block_id,
            stall_reason,
            cross_zone_halt,
            cross_zone_peers: self
                .verifier
                .as_ref()
                .map(CrossZoneVerifier::peer_statuses)
                .unwrap_or_default(),
        }
    }

    /// Atomically publish a new ingestion status for readers of `status`.
    fn set_status(&self, status: IndexerSyncStatus) {
        self.status.store(Arc::new(status));
    }

    /// Clears the persisted halt record once the block it names applies, or
    /// once a block at the recorded id applies under a different hash, which
    /// proves the record stale. Called only once the block is stored, never
    /// before. `pending_halt` mirrors the record so the hot path
    /// compares in memory instead of reading the store per block.
    fn clear_halt_for_block(&self, block: &Block, pending_halt: &mut Option<CrossZoneHalt>) {
        let Some(halt) = pending_halt.as_ref() else {
            return;
        };
        if halt.block_hash != block.header.hash && halt.block_id != block.header.block_id {
            return;
        }
        if halt.block_hash != block.header.hash {
            warn!(
                "Cross-zone halt record is stale: block {} applied with hash {}, not the recorded {}. Clearing it.",
                block.header.block_id, block.header.hash, halt.block_hash
            );
        }
        if let Err(err) = self.store.set_cross_zone_halt(&None) {
            warn!("Failed to clear cross-zone halt record: {err:#}");
            return;
        }
        *pending_halt = None;
    }

    /// The keys to record for an operator-listed block. Checked before
    /// verification: a listed block skips it entirely, so listing a hash also
    /// clears a dead-peer retry loop, not only a forged verdict. `None` when
    /// the hash is not listed.
    fn accept_listed(&self, block: &Block) -> Option<Vec<SeenKey>> {
        if !self
            .config
            .cross_zone_accept_unverified
            .contains(&block.header.hash)
        {
            return None;
        }
        error!(
            "Accepting block {} without cross-zone verification: hash {} is listed in cross_zone_accept_unverified.",
            block.header.block_id, block.header.hash
        );
        Some(self.verifier.as_ref().map_or_else(
            || CrossZoneVerifier::unverified_dispatch_keys(block),
            |verifier| verifier.accept_unverified(block),
        ))
    }

    /// Persists the halt record for a forged verdict and flips the status; the
    /// caller ends ingestion.
    fn handle_forged(
        &self,
        block: &Block,
        forged: &ForgedDispatch,
        pending_halt: &mut Option<CrossZoneHalt>,
    ) {
        error!(
            "Cross-zone verification failed for block {}: {forged}. Halting indexer ingestion.",
            block.header.block_id
        );
        let halt = CrossZoneHalt {
            block_id: block.header.block_id,
            block_hash: block.header.hash,
            src_zone: hex::encode(forged.src_zone),
            src_block_id: forged.src_block_id,
            src_tx_index: forged.src_tx_index,
            verdict: forged.verdict.clone(),
        };
        if let Err(err) = self.store.set_cross_zone_halt(&Some(halt.clone())) {
            error!("Failed to persist cross-zone halt record: {err:#}");
        }
        self.set_status(IndexerSyncStatus::halted(halt.to_string()));
        *pending_halt = Some(halt);
    }

    /// Parks on an inscription that could not be parsed as an L2 block:
    /// records the stall and flips the status. The validated tip stays frozen.
    ///
    /// Returns `false` if the stall could not be recorded durably; the caller
    /// must then hold the cursor and retry instead of advancing past the slot.
    fn park_undeserializable(&self, slot: Slot, error: std::io::Error) -> bool {
        let error = anyhow::Error::new(error);

        // use `:#` to get the entire error chain
        let reason = format!("{error:#}");
        error!("Failed to deserialize L2 block from zone-sdk: {reason}");
        if let Err(err) =
            self.store
                .record_stall(None, slot, BlockIngestError::Deserialize(reason.clone()))
        {
            error!("Failed to record stall reason: {err:#}");
            self.set_status(IndexerSyncStatus::error(format!("store error: {err:#}")));
            return false;
        }
        self.set_status(IndexerSyncStatus::stalled(format!(
            "failed to deserialize L2 block: {reason}"
        )));
        true
    }

    /// Fetches each of `digests` into the proof store from the first proof
    /// source holding it, checked against its digest.
    async fn fetch_proofs(&self, digests: &[ProofDigest]) {
        for digest in digests {
            for source in &self.proof_sources {
                match source
                    .get_proof(sequencer_service_protocol::ProofDigest(*digest))
                    .await
                {
                    Ok(Some(proof)) if proof.0.digest() == *digest => {
                        self.proofs.insert(&proof.0);
                        break;
                    }
                    Ok(_) => {}
                    Err(err) => warn!("Failed to fetch a proof from a proof source: {err}"),
                }
            }
        }
    }

    /// Rebuilds the fold from the store's settled state and tip, to re-read the
    /// channel from the entry of the last block the store applied.
    fn resume(&self) -> Result<Ingest> {
        let tip = self
            .store
            .get_last_block_id()?
            .map(|id| self.store.get_block_at_id(id))
            .transpose()?
            .flatten()
            .map(|block| Tip::from(&block));
        let chain = ChainState::from_final(
            self.store.recalculate_final_state()?,
            tip,
            self.proofs.clone(),
        );
        let resume = self.store.get_zone_cursor()?;
        let pending_halt = match self.store.get_cross_zone_halt() {
            Ok(halt) => halt,
            Err(err) => {
                warn!("Failed to read cross-zone halt record: {err:#}");
                None
            }
        };
        Ok(Ingest {
            read: resume.and_then(|(_, slot)| slot.checked_sub(Slot::from(1))),
            parent: chain.final_msg(),
            resume,
            chain,
            settled: VecDeque::new(),
            unserved: Vec::new(),
            pending_halt,
        })
    }

    /// Folds the finalized `entries` with the L1 LIB at `lib`, fetches the
    /// proofs the fold lacks, and hands what settles to the store in order.
    async fn advance(
        &self,
        ingest: &mut Ingest,
        entries: &[ChannelEntry],
        lib: Slot,
    ) -> (Vec<Block>, Step) {
        ingest.fold(entries, lib);
        let mut missing = ingest.chain.missing_proofs();
        while !missing.is_empty() && missing != ingest.unserved {
            self.fetch_proofs(&missing).await;
            if !ingest.chain.hydrate() {
                ingest.unserved = ingest.chain.missing_proofs();
                let lacking = ingest.unserved.len();
                error!(
                    "A held block is missing {lacking} proofs no proof source served. Retrying next pass."
                );
                self.set_status(IndexerSyncStatus::error(format!(
                    "a held block is missing {lacking} proofs"
                )));
                break;
            }
            missing = ingest.chain.missing_proofs();
        }
        // Hydration refolds without settling.
        ingest.fold(&[], lib);
        self.store_settled(ingest).await
    }

    /// Hands the settled blocks to the store in order, each through cross-zone
    /// verification, and moves the cursor to the entry of each one applied.
    async fn store_settled(&self, ingest: &mut Ingest) -> (Vec<Block>, Step) {
        let mut applied = Vec::new();
        while let Some(settled) = ingest.settled.front() {
            let block = settled.block();
            let slot = settled
                .slot()
                .expect("the indexer folds only final entries");
            // Re-derive and verify every cross-zone dispatch the block
            // carries before applying it, so the destination never trusts
            // a dispatch just because a sequencer signed the block: a
            // forged one halts ingestion rather than persisting invalid
            // state, while a replay is left to the inbox, which refuses it
            // on chain. An operator-listed block hash skips verification
            // entirely, ahead of it, so listing clears a dead-peer retry
            // loop as well as a forged verdict. The keys are marked seen
            // only once the block applies (below), so a block that does
            // not apply cannot poison the seen-set.
            let verified_keys = match self.accept_listed(block) {
                Some(keys) => keys,
                None => match &self.verifier {
                    Some(verifier) => match verifier.verify_block(block, slot).await {
                        Ok(keys) => keys,
                        Err(CrossZoneVerifyError::Forged(forged)) => {
                            self.handle_forged(block, &forged, &mut ingest.pending_halt);
                            return (applied, Step::Halted);
                        }
                        // Not judged either way yet, so retry rather than halt.
                        Err(err @ CrossZoneVerifyError::PeerUnavailable { .. }) => {
                            error!(
                                "Cross-zone verification of block {} stalled: {err}. Holding the cursor and retrying.",
                                block.header.block_id
                            );
                            self.set_status(IndexerSyncStatus::error(format!(
                                "cross-zone peer unavailable: {err}"
                            )));
                            return (applied, Step::Held);
                        }
                    },
                    None => Vec::new(),
                },
            };

            match self.store.put_settled_block(settled).await {
                Ok(stored @ (Stored::Written | Stored::Replayed)) => {
                    if let Some(verifier) = &self.verifier {
                        verifier.record_seen(verified_keys).await;
                    }
                    // Only an applied block may clear the halt record;
                    // clearing earlier would drop it for a block that
                    // never reaches the chain state.
                    self.clear_halt_for_block(block, &mut ingest.pending_halt);
                    if let Err(err) = self.store.set_zone_cursor(&(settled.msg(), slot)) {
                        warn!("Failed to persist indexer cursor: {err:#}");
                    }
                    // A replay was announced when it was first written.
                    if matches!(stored, Stored::Written) {
                        log::info!(
                            "Indexed L2 block {} at channel {}",
                            block.header.block_id,
                            self.config.channel_id
                        );
                        self.set_status(IndexerSyncStatus::syncing());
                        applied.push(block.clone());
                    }
                }
                Err(refusal @ (PutSettledError::Identity { .. } | PutSettledError::Parent(_))) => {
                    error!(
                        "The store refused settled block {}: {refusal}. Holding the cursor.",
                        block.header.block_id
                    );
                    self.set_status(IndexerSyncStatus::stalled(format!(
                        "the store refused settled block {}: {refusal}",
                        block.header.block_id
                    )));
                    return (applied, Step::Held);
                }
                Err(PutSettledError::Store(err)) => {
                    // Infrastructure error (DB read/write), not a bad block.
                    // will re-poll from the same cursor next cycle.
                    error!(
                        "Store error applying block {}: {err:#}",
                        block.header.block_id
                    );
                    self.set_status(IndexerSyncStatus::error(format!("store error: {err:#}")));
                    return (applied, Step::Held);
                }
            }
            ingest.settled.pop_front();
        }
        (applied, Step::Done)
    }

    pub fn subscribe_parse_block_stream(&self) -> impl futures::Stream<Item = Result<Block>> + '_ {
        let poll_interval = self.config.consensus_info_polling_interval;

        async_stream::stream! {
            let mut ingest = loop {
                match self.resume() {
                    Ok(ingest) => break ingest,
                    Err(err) => {
                        error!("Failed to rebuild the fold from the store: {err:#}");
                        self.set_status(IndexerSyncStatus::error(format!("store error: {err:#}")));
                        tokio::time::sleep(poll_interval).await;
                    }
                }
            };

            if let Some((msg, slot)) = &ingest.resume {
                log::info!("Resuming indexer after message {msg} at slot {slot:?}");
            } else {
                log::info!("Starting indexer from beginning of channel");
            }

            loop {
                ingest.unserved.clear();

                // What the last pass held goes to the store, and the proofs it
                // lacks are asked for again, before the fold reads on.
                if !ingest.settled.is_empty() || !ingest.chain.missing_proofs().is_empty() {
                    let (applied, step) = self.advance(&mut ingest, &[], Slot::genesis()).await;
                    for block in applied {
                        yield Ok(block);
                    }
                    match step {
                        Step::Done => {}
                        Step::Held => {
                            tokio::time::sleep(poll_interval).await;
                            continue;
                        }
                        Step::Halted => return,
                    }
                }

                let stream = match self.zone_indexer.next_messages(ingest.read).await {
                    Ok(s) => s,
                    Err(err) => {
                        error!("Failed to start zone-sdk next_messages stream: {err}");
                        self.set_status(IndexerSyncStatus::error(format!(
                            "cannot reach L1 / read channel: {err}"
                        )));
                        tokio::time::sleep(poll_interval).await;
                        continue;
                    }
                };
                let mut stream = std::pin::pin!(stream);

                let mut had_cycle_error = false;
                while let Some(batch) = stream.next().await {
                    let batch = match batch {
                        Ok(batch) => batch,
                        Err(err) => {
                            error!("Channel read failed, holding the cursor: {err}");
                            self.set_status(IndexerSyncStatus::error(format!(
                                "cannot read channel: {err}"
                            )));
                            had_cycle_error = true;
                            break;
                        }
                    };

                    let mut read = Some(batch.watermark);
                    let mut entries: Vec<ChannelEntry> = Vec::new();
                    for (msg, slot) in batch.messages {
                        let zone_block = match msg {
                            ZoneMessage::Block(b) => b,
                            // FIXME: will be handled in prep of decentralized sequencers
                            ZoneMessage::Deposit(_) | ZoneMessage::Withdraw(_) => continue,
                        };
                        if ingest.re_read(zone_block.id, slot) {
                            continue;
                        }

                        let block = match DigestedBlock::from_inscription(&zone_block.data) {
                            Ok(b) => Some(b),
                            Err(error) => {
                                // The stall must be durable before the cursor moves.
                                if !self.park_undeserializable(slot, error) {
                                    entries.retain(|entry| entry.slot < Some(slot));
                                    read = slot.checked_sub(Slot::from(1));
                                    had_cycle_error = true;
                                    break;
                                }
                                // L1 proceeds regardless
                                None
                            }
                        };
                        entries.push(ChannelEntry {
                            msg: zone_block.id,
                            parent: entries.last().map_or(ingest.parent, |entry| entry.msg),
                            signer: (!zone_block.signer.is_weak())
                                .then(|| zone_block.signer.to_bytes()),
                            slot: Some(slot),
                            block,
                        });
                    }

                    if let Some(lib) = read {
                        let (applied, step) = self.advance(&mut ingest, &entries, lib).await;
                        ingest.read = read;
                        for block in applied {
                            yield Ok(block);
                        }
                        match step {
                            Step::Done => {}
                            Step::Held => had_cycle_error = true,
                            Step::Halted => return,
                        }
                    }
                    if had_cycle_error {
                        break;
                    }
                }

                if had_cycle_error {
                    // The slot in progress is not finished, so the cursor stays
                    // below it and the next pass re-reads it whole.
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }

                // Stream drained. Stay Stalled if parked, and in error while a
                // held block lacks proofs; otherwise we are caught up.
                // A store error here must not be collapsed to "no stall recorded":
                // that would wrongly flip us to caught-up, so we log and hold state.
                match self.store.get_stall_reason() {
                    Ok(None) if ingest.chain.missing_proofs().is_empty() => {
                        self.set_status(IndexerSyncStatus::caught_up());
                    }
                    Ok(_) => {}
                    Err(err) => {
                        warn!("Failed to read stall reason after draining stream; not marking caught up: {err:#}");
                    }
                }
                tokio::time::sleep(poll_interval).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, num::NonZeroU32, time::Duration};

    use common::{HashType, block::HashableBlockData, transaction::LeeTransaction};
    use jsonrpsee::{
        RpcModule,
        server::{Server, ServerHandle},
        types::ErrorObjectOwned,
    };
    use lee::{
        PrivacyPreservingTransaction,
        privacy_preserving_transaction::{Message, WitnessSet, circuit::Proof},
    };
    use logos_blockchain_zone_sdk::Slot;

    use super::*;
    use crate::{
        block_store::store_block,
        config::{ChannelId, ClientConfig, EventFilterConfig, IndexerConfig},
    };

    mod settlement;

    fn unreachable_core(dir: &std::path::Path) -> IndexerCore {
        unreachable_core_accepting(dir, Vec::new())
    }

    fn unreachable_core_accepting(
        dir: &std::path::Path,
        cross_zone_accept_unverified: Vec<HashType>,
    ) -> IndexerCore {
        let config = IndexerConfig {
            consensus_info_polling_interval: Duration::from_secs(1),
            bedrock_config: ClientConfig {
                addr: "http://localhost:1".parse().expect("url"),
                auth: None,
            },
            proof_sources: Vec::new(),
            channel_id: ChannelId::from([1; 32]),
            allow_chain_reset: false,
            cross_zone: None,
            cross_zone_accept_unverified,
            peer_block_cache_window: NonZeroU32::new(1024).expect("1024 is nonzero"),
            event_filter: EventFilterConfig::default(),
        };
        IndexerCore::open(config, dir).expect("open core")
    }

    fn test_block(block_id: u64, timestamp: u64) -> Block {
        HashableBlockData {
            block_id,
            prev_block_hash: HashType([0; 32]),
            timestamp,
            transactions: vec![],
            reverted: Vec::new(),
        }
        .into_pending_block()
    }

    #[tokio::test]
    async fn cold_store_is_inconclusive() {
        // An empty store has no cursor, so there is nothing to compare: the check
        // must be Inconclusive (not Consistent), and it returns before any L1 read.
        let dir = tempfile::tempdir().expect("tempdir");
        let core = unreachable_core(dir.path());
        assert!(matches!(
            core.verify_chain_consistency().await.expect("verify"),
            ChainConsistency::Inconclusive
        ));
    }

    #[tokio::test]
    async fn parked_store_with_unreachable_node_is_inconclusive() {
        // Network failure is not evidence of a reset: a parked store must stay
        // parked (Inconclusive), not error out or trip the wipe path.
        let dir = tempfile::tempdir().expect("tempdir");
        let core = unreachable_core(dir.path());
        let parked = test_block(5, 42);
        core.store
            .record_stall(
                Some(&parked.header),
                Slot::from(1_000),
                BlockIngestError::EmptyBlock,
            )
            .expect("record stall");
        assert!(matches!(
            core.verify_chain_consistency().await.expect("verify"),
            ChainConsistency::Inconclusive
        ));
    }

    #[tokio::test]
    async fn caught_up_store_with_unreachable_node_is_inconclusive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let core = unreachable_core(dir.path());
        let genesis = common::test_utils::produce_dummy_block(1, None, vec![]);
        store_block(&core.store, &genesis, Slot::from(1_000)).await;
        core.store
            .set_zone_cursor(&(MsgId::root(), Slot::from(1_000)))
            .expect("set cursor");
        assert!(matches!(
            core.verify_chain_consistency().await.expect("verify"),
            ChainConsistency::Inconclusive
        ));
    }

    #[tokio::test]
    async fn startup_anchor_prefers_tip_slot_over_lagging_cursor() {
        // Cursor persist failures are warn-only, so the read cursor can lag the
        // tip by several blocks. The anchor must pair the tip with its own
        // inscription slot; pairing it with the stale cursor would make the scan
        // misread the chain's intermediate blocks as re-inscriptions.
        let dir = tempfile::tempdir().expect("tempdir");
        let core = unreachable_core(dir.path());

        let genesis = common::test_utils::produce_dummy_block(1, None, vec![]);
        store_block(&core.store, &genesis, Slot::from(1_000)).await;
        let block2 = common::test_utils::produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        store_block(&core.store, &block2, Slot::from(1_005)).await;
        let block3 = common::test_utils::produce_dummy_block(3, Some(block2.header.hash), vec![]);
        store_block(&core.store, &block3, Slot::from(1_010)).await;

        // Cursor last persisted at the genesis slot: two blocks behind the tip.
        core.store
            .set_zone_cursor(&(MsgId::root(), Slot::from(1_000)))
            .expect("set cursor");

        let anchor = core.get_startup_anchor().expect("anchor").expect("present");
        let expected = Anchor::new(Slot::from(1_010), Some((3, block3.header.hash)));
        assert_eq!(anchor, expected);
    }

    /// An inbox dispatch transaction with fixed source coordinates, so blocks
    /// in these tests carry a decodable dispatch key.
    fn dispatch_tx() -> common::transaction::LeeTransaction {
        let receiver_id = programs::ping_receiver_account_id();
        common::transaction::LeeTransaction::Public(cross_zone::build_dispatch_from_emission(
            &cross_zone::EmissionSource {
                src_zone: [2; 32],
                src_block_id: 5,
                src_block_hash: [3; 32],
                src_tx_index: 0,
                src_account_id: programs::ping_sender_account_id(),
            },
            receiver_id,
            &[
                lee::Actor::new(
                    ping_core::receiver_config_account_id(receiver_id),
                    receiver_id,
                ),
                lee::Actor::new(ping_core::ping_record_pda(receiver_id), receiver_id),
            ],
            b"hi".to_vec(),
        ))
    }

    fn forged_verdict() -> ForgedDispatch {
        ForgedDispatch {
            src_zone: [2; 32],
            src_block_id: 5,
            src_tx_index: 0,
            verdict: "re-derivation mismatch".to_owned(),
        }
    }

    #[tokio::test]
    async fn a_forged_verdict_persists_a_halt_record_and_halts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let core = unreachable_core(dir.path());
        let block = common::test_utils::produce_dummy_block(9, None, vec![dispatch_tx()]);

        let mut pending = None;
        core.handle_forged(&block, &forged_verdict(), &mut pending);

        let halt = core
            .store
            .get_cross_zone_halt()
            .expect("get")
            .expect("the halt record is persisted");
        assert_eq!(halt.block_id, 9);
        assert_eq!(halt.block_hash, block.header.hash);
        assert_eq!(halt.src_zone, hex::encode([2_u8; 32]));
        assert_eq!(halt.src_block_id, 5);
        assert_eq!(halt.src_tx_index, 0);
        assert_eq!(pending, Some(halt.clone()));

        let status = core.status();
        assert_eq!(status.sync.state, crate::status::IndexerSyncState::Halted);
        assert_eq!(status.cross_zone_halt, Some(halt));
    }

    #[tokio::test]
    async fn startup_with_a_halt_record_reports_halted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let core = unreachable_core(dir.path());
        let block = common::test_utils::produce_dummy_block(9, None, vec![dispatch_tx()]);
        let mut pending = None;
        core.handle_forged(&block, &forged_verdict(), &mut pending);
        drop(core);

        let reopened = unreachable_core(dir.path());
        let status = reopened.status();
        assert_eq!(status.sync.state, crate::status::IndexerSyncState::Halted);
        let reason = status
            .sync
            .last_error
            .expect("the stored reason is reported");
        assert!(reason.contains("re-derivation mismatch"), "{reason}");
        assert!(status.cross_zone_halt.is_some());
    }

    #[tokio::test]
    async fn an_accept_listed_block_is_taken_before_verification() {
        // The gate runs ahead of `verify_block`, so a listed block never
        // touches the verifier: it clears a dead-peer PeerUnavailable loop
        // just as it clears a forged verdict.
        let dir = tempfile::tempdir().expect("tempdir");
        let block = common::test_utils::produce_dummy_block(9, None, vec![dispatch_tx()]);
        let core = unreachable_core_accepting(dir.path(), vec![block.header.hash]);

        let keys = core
            .accept_listed(&block)
            .expect("a listed hash is accepted");
        assert_eq!(
            keys,
            CrossZoneVerifier::unverified_dispatch_keys(&block),
            "the block's dispatch keys are what gets marked seen"
        );
        assert_eq!(keys.len(), 1);

        // The override names one hash only; any other block is not accepted.
        let other = common::test_utils::produce_dummy_block(
            10,
            Some(block.header.hash),
            vec![dispatch_tx()],
        );
        assert!(core.accept_listed(&other).is_none());
    }

    #[tokio::test]
    async fn the_halt_record_clears_only_after_the_block_applies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let block = common::test_utils::produce_dummy_block(9, None, vec![dispatch_tx()]);
        let core = unreachable_core_accepting(dir.path(), vec![block.header.hash]);

        // A previous run halted on this block; the operator then listed it.
        let mut pending = None;
        core.handle_forged(&block, &forged_verdict(), &mut pending);

        // Acceptance alone must not clear the record: the block has not
        // applied yet, and a crash before apply must re-halt identically.
        core.accept_listed(&block).expect("listed");
        assert!(core.store.get_cross_zone_halt().expect("get").is_some());
        assert!(pending.is_some());

        // What the ingest loop does once the block is stored.
        core.clear_halt_for_block(&block, &mut pending);
        assert!(core.store.get_cross_zone_halt().expect("get").is_none());
        assert!(pending.is_none());
    }

    #[tokio::test]
    async fn a_halting_block_that_applies_clears_the_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let core = unreachable_core(dir.path());
        let block = common::test_utils::produce_dummy_block(9, None, vec![dispatch_tx()]);
        let mut pending = None;
        core.handle_forged(&block, &forged_verdict(), &mut pending);

        // A different block applying leaves the record alone.
        let other = common::test_utils::produce_dummy_block(8, None, vec![]);
        core.clear_halt_for_block(&other, &mut pending);
        assert!(core.store.get_cross_zone_halt().expect("get").is_some());

        // The halting block itself applying clears it.
        core.clear_halt_for_block(&block, &mut pending);
        assert!(core.store.get_cross_zone_halt().expect("get").is_none());
        assert!(pending.is_none());
    }

    #[tokio::test]
    async fn a_different_hash_applying_at_the_halted_id_clears_the_stale_record() {
        // The channel can come to serve a different block at the recorded id
        // (e.g. after a chain reset); once one applies, the record provably
        // describes a block the chain no longer carries.
        let dir = tempfile::tempdir().expect("tempdir");
        let core = unreachable_core(dir.path());
        let block = common::test_utils::produce_dummy_block(9, None, vec![dispatch_tx()]);
        let mut pending = None;
        core.handle_forged(&block, &forged_verdict(), &mut pending);

        let different = common::test_utils::produce_dummy_block(9, None, vec![]);
        assert_ne!(different.header.hash, block.header.hash);
        core.clear_halt_for_block(&different, &mut pending);
        assert!(core.store.get_cross_zone_halt().expect("get").is_none());
        assert!(pending.is_none());
    }

    fn private_transaction(proof: &Proof) -> LeeTransaction {
        LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(
            Message::default(),
            WitnessSet::from_raw_parts(vec![], proof.clone()),
        ))
    }

    /// A sequencer that serves only `getProof`, from `proofs`.
    async fn proof_source(proofs: HashMap<ProofDigest, Proof>) -> (SequencerClient, ServerHandle) {
        let mut sequencer = RpcModule::new(proofs);
        sequencer
            .register_method("getProof", |params, held, _| {
                let digest = params.one::<sequencer_service_protocol::ProofDigest>()?;
                Ok::<_, ErrorObjectOwned>(
                    held.get(&digest.0)
                        .cloned()
                        .map(sequencer_service_protocol::Proof),
                )
            })
            .unwrap();
        let server = Server::builder().build("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let client = SequencerClientBuilder::default()
            .build(format!("http://{address}"))
            .unwrap();
        (client, server.start(sequencer))
    }

    /// `block` hydrated from the proof store once the proofs it lacks are fetched.
    async fn hydrate(core: &IndexerCore, block: &DigestedBlock) -> Result<Block, Vec<ProofDigest>> {
        if let Err(missing) = block.hydrate(|digest| core.proofs.get(digest)) {
            core.fetch_proofs(&missing).await;
        }
        block.hydrate(|digest| core.proofs.get(digest))
    }

    #[tokio::test]
    async fn wrong_bytes_do_not_satisfy_a_digest_a_later_source_does_and_unserved_ones_are_named() {
        let dir = tempfile::tempdir().expect("tempdir");
        let proof = Proof::from_inner(vec![1; 32]);
        let missing = Proof::from_inner(vec![2; 32]);
        let block =
            common::test_utils::produce_dummy_block(1, None, vec![private_transaction(&proof)]);
        let with_missing = common::test_utils::produce_dummy_block(
            1,
            None,
            vec![private_transaction(&proof), private_transaction(&missing)],
        );
        let wrong_bytes = HashMap::from([(proof.digest(), Proof::from_inner(vec![3; 32]))]);
        let (wrong, _wrong_sequencer) = proof_source(wrong_bytes).await;
        let (right, _right_sequencer) =
            proof_source(HashMap::from([(proof.digest(), proof.clone())])).await;
        let mut core = unreachable_core(dir.path());

        core.proof_sources = vec![wrong.clone()];
        assert_eq!(
            hydrate(&core, &block.digested()).await.err(),
            Some(vec![proof.digest()])
        );

        core.proof_sources = vec![wrong, right];
        assert_eq!(
            hydrate(&core, &with_missing.digested()).await.err(),
            Some(vec![missing.digest()])
        );
        let hydrated = hydrate(&core, &block.digested())
            .await
            .expect("the later source holds the proof");
        assert_eq!(hydrated.body, block.body);
    }
}
