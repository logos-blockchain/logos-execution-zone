use std::{path::Path, sync::Arc};

use anyhow::Result;
use arc_swap::ArcSwap;
pub use chain_state::{AcceptOutcome, BlockIngestError, StallReason};
use chain_state::{Anchor, ChainConsistency};
use common::block::Block;
// TODO: Remove after testnet
use futures::StreamExt as _;
use log::{error, warn};
use logos_blockchain_zone_sdk::{
    CommonHttpClient, Slot, ZoneMessage, adapter::NodeHttpClient, indexer::ZoneIndexer,
};
use retry::ApplyRetryGate;

use crate::{
    block_store::IndexerStore,
    config::IndexerConfig,
    cross_zone_verifier::{CrossZoneVerifier, CrossZoneVerifyError, ForgedDispatch, SeenKey},
    status::{CrossZoneHalt, IndexerStatus, IndexerSyncStatus},
};

pub mod block_store;
pub mod config;
pub mod cross_zone_verifier;
mod retry;
pub mod status;

/// Consecutive failed apply attempts of the same block before parking.
const APPLY_RETRY_LIMIT: u32 = 3;

/// Which slot the ingest loop is currently inside, so the read cursor only ever
/// moves on a slot boundary.
///
/// One L1 slot can carry several L2 blocks, and the channel stream resumes
/// *after* the stored slot. Advancing the cursor as each block is handled would
/// therefore put a later block in the same slot beyond the cursor whenever a
/// pass ends early, and nothing would ever read it again.
#[derive(Default)]
struct SlotProgress(Option<Slot>);

#[derive(Clone)]
pub struct IndexerCore {
    pub zone_indexer: Arc<ZoneIndexer<NodeHttpClient>>,
    /// Direct node handle for queries outside `ZoneIndexer`'s streaming API.
    pub node: NodeHttpClient,
    pub config: IndexerConfig,
    pub store: IndexerStore,
    /// Live ingestion status; updated by the ingest stream, read by `status`.
    pub status: Arc<ArcSwap<IndexerSyncStatus>>,
    /// Option B cross-zone verifier; `None` when cross-zone messaging is disabled.
    pub verifier: Option<CrossZoneVerifier>,
}

impl SlotProgress {
    /// Records that a message from `slot` is being handled, returning the slot
    /// that just completed, if this message begins a new one.
    fn enter(&mut self, slot: Slot) -> Option<Slot> {
        if self.0 == Some(slot) {
            return None;
        }
        self.0.replace(slot)
    }

    /// The slot in progress when the stream drained cleanly, which is therefore
    /// complete. Not called when a pass ends early: that slot must be re-read.
    const fn drained(self) -> Option<Slot> {
        self.0
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
        let node = NodeHttpClient::new(
            CommonHttpClient::new(basic_auth),
            config.bedrock_config.addr.clone(),
        );
        let zone_indexer = ZoneIndexer::new(config.channel_id, node.clone());

        // Cross-zone programs are base builtins, and their config accounts are
        // reconstructed by replaying the genesis block's InitConfig transactions;
        // neither is seeded here. Only bridge-lock holdings (source side), not
        // produced by any transaction, are still seeded directly.
        let genesis_accounts: Vec<_> = config
            .bridge_lock_holdings
            .iter()
            .map(|holding| cross_zone::build_holding_account(holding.holder, holding.amount))
            .collect();

        // Option B verifier: re-derives each cross-zone dispatch from the peer's
        // finalized blocks. `None` when cross-zone messaging is disabled.
        let verifier = CrossZoneVerifier::start(&config);

        let store = IndexerStore::open_db(&home, genesis_accounts)?;
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
        let Some(slot) = self
            .store
            .get_tip_slot()?
            .map_or_else(|| self.store.get_zone_cursor(), |slot| Ok(Some(slot)))?
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

    /// Advances the in-memory L1 read cursor past `slot` and persists it.
    /// A persist failure is only logged: the worst case is re-reading a batch
    /// after a restart, which ingestion handles idempotently.
    fn advance_cursor(&self, cursor: &mut Option<Slot>, slot: Slot) {
        *cursor = Some(slot);
        if let Err(err) = self.store.set_zone_cursor(&slot) {
            warn!("Failed to persist indexer cursor: {err:#}");
        }
    }

    /// Clears the persisted halt record once the block it names applies, or
    /// once a block at the recorded id applies under a different hash, which
    /// proves the record stale. Called only after [`AcceptOutcome::Applied`],
    /// never before apply. `pending_halt` mirrors the record so the hot path
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

    pub fn subscribe_parse_block_stream(&self) -> impl futures::Stream<Item = Result<Block>> + '_ {
        let poll_interval = self.config.consensus_info_polling_interval;
        let initial_cursor = self
            .store
            .get_zone_cursor()
            .expect("Failed to load zone-sdk indexer cursor");

        async_stream::stream! {
            let mut cursor = initial_cursor;
            let mut retry_gate = ApplyRetryGate::new();
            // In-memory mirror of the persisted halt record, so clearing it
            // when the recorded block later applies needs no per-block read.
            let mut pending_halt = match self.store.get_cross_zone_halt() {
                Ok(halt) => halt,
                Err(err) => {
                    warn!("Failed to read cross-zone halt record: {err:#}");
                    None
                }
            };

            if let Some(slot) = &cursor {
                log::info!("Resuming indexer from cursor {slot:?}");
            } else {
                log::info!("Starting indexer from beginning of channel");
            }

            loop {
                let stream = match self.zone_indexer.next_messages(cursor).await {
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

                let mut announced_syncing = false;
                let mut had_cycle_error = false;
                // The slot being consumed: every message of it seen so far is
                // handled, but another may follow, so the cursor may not move
                // onto it yet. One L1 slot can carry several L2 blocks, and the
                // stream resumes *after* the stored slot, so advancing inside a
                // slot would put a later message in it beyond the cursor
                // for ever if this pass ends early.
                let mut in_progress = SlotProgress::default();

                while let Some((msg, slot)) = stream.next().await {
                    // A message from a later slot means the previous one is complete.
                    if let Some(done) = in_progress.enter(slot) {
                        self.advance_cursor(&mut cursor, done);
                    }

                    if !announced_syncing {
                        self.set_status(IndexerSyncStatus::syncing());
                        announced_syncing = true;
                    }

                    let zone_block = match msg {
                        ZoneMessage::Block(b) => b,
                        // FIXME: will be handled in prep of decentralized sequencers
                        ZoneMessage::Deposit(_) | ZoneMessage::Withdraw(_) => continue,
                    };

                    let block: Block = match borsh::from_slice(&zone_block.data) {
                        Ok(b) => b,
                        Err(error) => {
                            // The stall must be durable before the cursor moves.
                            if !self.park_undeserializable(slot, error) {
                                had_cycle_error = true;
                                break;
                            }
                            // L1 proceeds regardless
                            continue;
                        }
                    };

                    // Re-derive and verify every cross-zone dispatch the block
                    // carries before applying it, so the destination never trusts
                    // a dispatch just because a sequencer signed the block: a
                    // forged one halts ingestion rather than persisting invalid
                    // state, while a replay is accepted since the inbox no-ops it
                    // on chain. An operator-listed block hash skips verification
                    // entirely, ahead of it, so listing clears a dead-peer retry
                    // loop as well as a forged verdict. The keys are marked seen
                    // only once the block applies (below), so a block that does
                    // not apply cannot poison the seen-set.
                    let verified_keys = match self.accept_listed(&block) {
                        Some(keys) => keys,
                        None => match &self.verifier {
                            Some(verifier) => match verifier.verify_block(&block, slot).await {
                                Ok(keys) => keys,
                                Err(CrossZoneVerifyError::Forged(forged)) => {
                                    self.handle_forged(&block, &forged, &mut pending_halt);
                                    return;
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
                                    had_cycle_error = true;
                                    break;
                                }
                            },
                            None => Vec::new(),
                        },
                    };

                    match self.store.accept_block(&block, slot).await {
                        Ok(AcceptOutcome::Applied) => {
                            if let Some(verifier) = &self.verifier {
                                verifier.record_seen(verified_keys).await;
                            }
                            // Only an applied block may clear the halt record;
                            // clearing earlier would drop it for a block that
                            // never reaches the chain state.
                            self.clear_halt_for_block(&block, &mut pending_halt);
                            retry_gate.reset();
                            log::info!("Indexed L2 block {} at channel {}", block.header.block_id, self.config.channel_id);
                            self.set_status(IndexerSyncStatus::syncing());
                            yield Ok(block);
                        }
                        Ok(AcceptOutcome::AlreadyApplied) => {
                            log::info!(
                                "Skipping already-applied block {}",
                                block.header.block_id
                            );
                        }
                        Ok(AcceptOutcome::Parked(ingest_err)) => {
                            error!(
                                "Parked at block {}: {ingest_err}",
                                block.header.block_id
                            );
                            self.set_status(IndexerSyncStatus::stalled(ingest_err.to_string()));
                            // L1 proceeds regardless
                        }
                        Ok(AcceptOutcome::RetryableFailure(ingest_err)) => {
                            let attempts = retry_gate.register_failure(block.header.block_id);
                            if attempts >= APPLY_RETRY_LIMIT {
                                error!(
                                    "Parked at block {} after {attempts} failed apply attempts: {ingest_err}",
                                    block.header.block_id
                                );
                                // The stall must be durable before the cursor moves.
                                if let Err(err) = self.store.record_stall(
                                    Some(&block.header),
                                    slot,
                                    ingest_err.clone(),
                                ) {
                                    error!(
                                        "Failed to record stall reason for block {}: {err:#}",
                                        block.header.block_id
                                    );
                                    self.set_status(IndexerSyncStatus::error(format!(
                                        "store error: {err:#}"
                                    )));
                                    had_cycle_error = true;
                                    break;
                                }
                                self.set_status(IndexerSyncStatus::stalled(ingest_err.to_string()));
                                retry_gate.reset();
                            } else {
                                error!(
                                    "Failed to apply block {} (attempt {attempts}/{APPLY_RETRY_LIMIT}), will retry: {ingest_err}",
                                    block.header.block_id
                                );
                                self.set_status(IndexerSyncStatus::error(format!(
                                    "apply failed, retrying: {ingest_err}"
                                )));
                                had_cycle_error = true;
                                break;
                            }
                        }
                        Err(err) => {
                            // Infrastructure error (DB read/write), not a bad block.
                            // will re-poll from the same cursor next cycle.
                            error!(
                                "Store error applying block {}: {err:#}",
                                block.header.block_id
                            );
                            self.set_status(IndexerSyncStatus::error(format!(
                                "store error: {err:#}"
                            )));
                            had_cycle_error = true;
                            break;
                        }
                    }
                }

                if had_cycle_error {
                    // The slot in progress is not finished, so the cursor stays
                    // below it and the next pass re-reads it whole.
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }

                // The stream drained cleanly, so the slot in progress completed too.
                if let Some(done) = in_progress.drained() {
                    self.advance_cursor(&mut cursor, done);
                }

                // Stream drained. Stay Stalled if parked; otherwise we are caught up.
                // A store error here must not be collapsed to "no stall recorded":
                // that would wrongly flip us to caught-up, so we log and hold state.
                match self.store.get_stall_reason() {
                    Ok(None) => self.set_status(IndexerSyncStatus::caught_up()),
                    Ok(Some(_)) => {}
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
    use std::{num::NonZeroU32, time::Duration};

    use common::{HashType, block::HashableBlockData};
    use logos_blockchain_zone_sdk::Slot;

    use super::*;
    use crate::config::{ChannelId, ClientConfig, IndexerConfig};

    /// The cursor must not move while more of the same slot may still arrive.
    ///
    /// Two L2 blocks in one L1 slot: the first applies, the second stalls on an
    /// unavailable peer and the pass retries. If handling the first had advanced
    /// the cursor onto the slot, the retry would resume past it and the second
    /// block would never be read again, silently losing whatever it carried.
    #[test]
    fn a_slot_is_only_left_behind_once_it_is_finished() {
        let mut progress = SlotProgress::default();
        let slot = Slot::from(7);

        assert_eq!(
            progress.enter(slot),
            None,
            "nothing precedes the first slot"
        );
        assert_eq!(
            progress.enter(slot),
            None,
            "a second message in the same slot must not release it"
        );

        // The pass ends early here, so `drained` is never called and the cursor
        // is still below slot 7: the next pass re-reads it whole.
    }

    #[test]
    fn a_completed_slot_is_released_when_the_next_one_starts() {
        let mut progress = SlotProgress::default();

        assert_eq!(progress.enter(Slot::from(3)), None);
        assert_eq!(progress.enter(Slot::from(3)), None);
        assert_eq!(
            progress.enter(Slot::from(4)),
            Some(Slot::from(3)),
            "slot 3 is complete once a message from slot 4 arrives"
        );
        assert_eq!(progress.drained(), Some(Slot::from(4)));
    }

    #[test]
    fn draining_an_untouched_stream_releases_nothing() {
        assert_eq!(SlotProgress::default().drained(), None);
    }

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
            channel_id: ChannelId::from([1; 32]),
            allow_chain_reset: false,
            cross_zone: None,
            cross_zone_accept_unverified,
            peer_block_cache_window: NonZeroU32::new(1024).expect("1024 is nonzero"),
            bridge_lock_holdings: Vec::new(),
        };
        IndexerCore::open(config, dir).expect("open core")
    }

    fn test_block(block_id: u64, timestamp: u64) -> Block {
        HashableBlockData {
            block_id,
            prev_block_hash: HashType([0; 32]),
            timestamp,
            transactions: vec![],
        }
        .into_pending_block(&lee::PrivateKey::try_new([7; 32]).expect("valid key"))
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
        assert!(matches!(
            core.store
                .accept_block(&genesis, Slot::from(1_000))
                .await
                .expect("accept"),
            AcceptOutcome::Applied
        ));
        core.store
            .set_zone_cursor(&Slot::from(1_000))
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
        core.store
            .accept_block(&genesis, Slot::from(1_000))
            .await
            .expect("accept");
        let block2 = common::test_utils::produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        core.store
            .accept_block(&block2, Slot::from(1_005))
            .await
            .expect("accept");
        let block3 = common::test_utils::produce_dummy_block(3, Some(block2.header.hash), vec![]);
        core.store
            .accept_block(&block3, Slot::from(1_010))
            .await
            .expect("accept");

        // Cursor last persisted at the genesis slot: two blocks behind the tip.
        core.store
            .set_zone_cursor(&Slot::from(1_000))
            .expect("set cursor");

        let anchor = core.get_startup_anchor().expect("anchor").expect("present");
        let expected = Anchor::new(Slot::from(1_010), Some((3, block3.header.hash)));
        assert_eq!(anchor, expected);
    }

    /// An inbox dispatch transaction with fixed source coordinates, so blocks
    /// in these tests carry a decodable dispatch key.
    fn dispatch_tx() -> common::transaction::LeeTransaction {
        let receiver_id = programs::ping_receiver().id();
        common::transaction::LeeTransaction::Public(cross_zone::build_dispatch_from_emission(
            &cross_zone::EmissionSource {
                src_zone: [2; 32],
                src_block_id: 5,
                src_block_hash: [3; 32],
                src_tx_index: 0,
                src_account_id: program_loader_core::immutable_deploy_account_id(
                    programs::ping_sender().id(),
                ),
            },
            receiver_id,
            &[
                ping_core::receiver_config_account_id(receiver_id).into_value(),
                ping_core::ping_record_pda(receiver_id).into_value(),
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

        // What the ingest loop does on AcceptOutcome::Applied.
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
}
