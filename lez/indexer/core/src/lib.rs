use std::{path::Path, sync::Arc};

use anyhow::Result;
use arc_swap::ArcSwap;
pub use chain_state::{AcceptOutcome, BlockIngestError, StallReason};
use chain_state::{Anchor, ChainConsistency, consistency::checkpoint_eq};
use common::block::Block;
// TODO: Remove after testnet
use futures::StreamExt as _;
use log::{error, warn};
use logos_blockchain_zone_sdk::{
    CommonHttpClient, Slot, ZoneMessage,
    adapter::NodeHttpClient,
    sequencer::{SequencerCheckpoint, ZoneSequencer},
};
use retry::ApplyRetryGate;
use tokio::sync::Mutex;

use crate::{
    block_store::IndexerStore,
    config::IndexerConfig,
    cross_zone_verifier::{CrossZoneVerifier, CrossZoneVerifyError},
    status::{IndexerStatus, IndexerSyncStatus},
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
struct CheckpointProgress(Option<SequencerCheckpoint>);

#[derive(Clone)]
pub struct IndexerCore {
    pub zone_indexer: Arc<Mutex<ZoneSequencer<NodeHttpClient>>>,
    /// Direct node handle for queries outside `ZoneSequencer`'s streaming API.
    pub node: NodeHttpClient,
    pub config: IndexerConfig,
    pub store: IndexerStore,
    /// Live ingestion status; updated by the ingest stream, read by `status`.
    pub status: Arc<ArcSwap<IndexerSyncStatus>>,
    /// Option B cross-zone verifier; `None` when cross-zone messaging is disabled.
    pub verifier: Option<CrossZoneVerifier>,
}

impl CheckpointProgress {
    /// Records that a message from `checkpoint` is being handled, returning the checkpoint
    /// that just completed, if this message begins a new one.
    fn enter(&mut self, checkpoint: SequencerCheckpoint) -> Option<SequencerCheckpoint> {
        // Equality is not implemented for `SequencerCheckpoint`
        if self.0.is_some() {
            let ch_ref = self.0.as_ref().unwrap();
            if checkpoint_eq(ch_ref, &checkpoint) {
                return None;
            }
        }
        self.0.replace(checkpoint)
    }

    /// The checkpoint in progress when the stream drained cleanly, which is therefore
    /// complete. Not called when a pass ends early: that checkpoint must be re-read.
    fn drained(self) -> Option<SequencerCheckpoint> {
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
        let zone_indexer =
            chain_state::consistency::new_indexer(config.channel_id, node.clone(), None);

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

        Ok(Self {
            zone_indexer: Arc::new(Mutex::new(zone_indexer)),
            store: IndexerStore::open_db(&home, genesis_accounts)?,
            node,
            config,
            status: Arc::new(ArcSwap::from_pointee(IndexerSyncStatus::starting())),
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
                stall.checkpoint,
                stall.block_id.zip(stall.block_hash),
            )));
        }

        // not stalled, so anchor on the tip at its own inscription slot
        let Some(checkpoint) = self.store.get_tip_checkpoint()?.map_or_else(
            || self.store.get_zone_cursor(),
            |checkpoint| Ok(Some(checkpoint)),
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
        Ok(Some(Anchor::new(
            checkpoint,
            Some((tip_id, tip.header.hash)),
        )))
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
        IndexerStatus {
            sync,
            indexed_block_id,
            stall_reason,
        }
    }

    /// Atomically publish a new ingestion status for readers of `status`.
    fn set_status(&self, status: IndexerSyncStatus) {
        self.status.store(Arc::new(status));
    }

    /// Advances the in-memory L1 read cursor past `slot` and persists it.
    /// A persist failure is only logged: the worst case is re-reading a batch
    /// after a restart, which ingestion handles idempotently.
    fn advance_cursor(&self, cursor: &mut Option<Slot>, checkpoint: SequencerCheckpoint) {
        *cursor = Some(checkpoint.lib_slot);
        if let Err(err) = self.store.set_zone_cursor(&checkpoint) {
            warn!("Failed to persist indexer cursor: {err:#}");
        }
    }

    /// Parks on an inscription that could not be parsed as an L2 block:
    /// records the stall and flips the status. The validated tip stays frozen.
    ///
    /// Returns `false` if the stall could not be recorded durably; the caller
    /// must then hold the cursor and retry instead of advancing past the slot.
    fn park_undeserializable(
        &self,
        checkpoint: SequencerCheckpoint,
        error: std::io::Error,
    ) -> bool {
        let error = anyhow::Error::new(error);

        // use `:#` to get the entire error chain
        let reason = format!("{error:#}");
        error!("Failed to deserialize L2 block from zone-sdk: {reason}");
        if let Err(err) = self.store.record_stall(
            None,
            checkpoint,
            BlockIngestError::Deserialize(reason.clone()),
        ) {
            error!("Failed to record stall reason: {err:#}");
            self.set_status(IndexerSyncStatus::error(format!("store error: {err:#}")));
            return false;
        }
        self.set_status(IndexerSyncStatus::stalled(format!(
            "failed to deserialize L2 block: {reason}"
        )));
        true
    }

    /// Warning: locks indexer during operation.
    pub fn subscribe_parse_block_stream(
        &mut self,
    ) -> impl futures::Stream<Item = Result<Block>> + '_ {
        let poll_interval = self.config.consensus_info_polling_interval;
        let initial_cursor = self
            .store
            .get_zone_cursor()
            .expect("Failed to load zone-sdk indexer cursor");

        async_stream::stream! {
            let mut cursor = initial_cursor.map(|ch| ch.lib_slot);
            let mut retry_gate = ApplyRetryGate::new();

            if let Some(slot) = &cursor {
                log::info!("Resuming indexer from cursor {slot:?}");
            } else {
                log::info!("Starting indexer from beginning of channel");
            }

            loop {
                let mut write_lock = self.zone_indexer.lock().await;
                let stream =
                    chain_state::consistency::next_messages(&mut write_lock).await;

                //let stream = chain_state::consistency::next_messages(&mut self.zone_indexer).await;
                let mut stream = std::pin::pin!(stream);

                let mut announced_syncing = false;
                let mut had_cycle_error = false;
                // The slot being consumed: every message of it seen so far is
                // handled, but another may follow, so the cursor may not move
                // onto it yet. One L1 slot can carry several L2 blocks, and the
                // stream resumes *after* the stored slot, so advancing inside a
                // slot would put a later message in it beyond the cursor
                // for ever if this pass ends early.
                let mut in_progress = CheckpointProgress::default();

                while let Some((
                            msg,
                            checkpoint,
                        )) = stream.next().await
                {
                    // A message from a later checkpoint means the previous one is complete.
                    if let Some(done) = in_progress.enter(checkpoint.clone()) {
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
                            if !self.park_undeserializable(checkpoint.clone(), error) {
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
                    // on chain. The verified keys are marked seen only once the
                    // block applies (below), so a block that does not apply
                    // cannot poison the seen-set.
                    let verified_keys = match &self.verifier {
                        Some(verifier) => match verifier.verify_block(&block).await {
                            Ok(keys) => keys,
                            Err(err @ CrossZoneVerifyError::Forged(_)) => {
                                error!(
                                    "Cross-zone verification failed for block {}: {err}. Halting indexer ingestion.",
                                    block.header.block_id
                                );
                                self.set_status(IndexerSyncStatus::error(format!(
                                    "cross-zone verification failed: {err}"
                                )));
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
                    };

                    match self.store.accept_block(&block, checkpoint.clone()).await {
                        Ok(AcceptOutcome::Applied) => {
                            if let Some(verifier) = &self.verifier {
                                verifier.record_seen(verified_keys).await;
                            }
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
                                    checkpoint.clone(),
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
    use std::time::Duration;

    use common::{HashType, block::HashableBlockData};
    use logos_blockchain_zone_sdk::{Slot, node_types::MsgId};

    use super::*;
    use crate::config::{ChannelId, ClientConfig, IndexerConfig};

    fn checkpoint(slot: u64) -> SequencerCheckpoint {
        SequencerCheckpoint {
            last_msg_id: MsgId::from([0_u8; 32]),
            pending_txs: vec![],
            lib: [1_u8; 32].into(),
            lib_slot: Slot::from(slot),
        }
    }

    /// The cursor must not move while more of the same checkpoint may still arrive.
    ///
    /// Two L2 blocks in one L1 checkpoint: the first applies, the second stalls on an
    /// unavailable peer and the pass retries. If handling the first had advanced
    /// the cursor onto the checkpoint, the retry would resume past it and the second
    /// block would never be read again, silently losing whatever it carried.
    #[test]
    fn a_checkpoint_is_only_left_behind_once_it_is_finished() {
        let mut progress = CheckpointProgress::default();
        let checkpoint = checkpoint(7);

        assert!(
            progress.enter(checkpoint.clone()).is_none(),
            "nothing precedes the first checkpoint"
        );
        assert!(
            progress.enter(checkpoint).is_none(),
            "a second message in the same checkpoint must not release it"
        );

        // The pass ends early here, so `drained` is never called and the cursor
        // is still below checkpoint 7: the next pass re-reads it whole.
    }

    #[test]
    fn a_completed_checkpoint_is_released_when_the_next_one_starts() {
        let mut progress = CheckpointProgress::default();

        assert!(progress.enter(checkpoint(3)).is_none());
        assert!(progress.enter(checkpoint(3)).is_none());
        assert!(
            checkpoint_eq(&progress.enter(checkpoint(4)).unwrap(), &checkpoint(3)),
            "slot 3 is complete once a message from slot 4 arrives"
        );
        assert!(checkpoint_eq(&progress.drained().unwrap(), &checkpoint(4)));
    }

    #[test]
    fn draining_an_untouched_stream_releases_nothing() {
        assert!(CheckpointProgress::default().drained().is_none());
    }

    fn unreachable_core(dir: &std::path::Path) -> IndexerCore {
        let config = IndexerConfig {
            consensus_info_polling_interval: Duration::from_secs(1),
            bedrock_config: ClientConfig {
                addr: "http://localhost:1".parse().expect("url"),
                auth: None,
            },
            channel_id: ChannelId::from([1; 32]),
            allow_chain_reset: false,
            cross_zone: None,
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
                checkpoint(1_000),
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
                .accept_block(&genesis, checkpoint(1_000))
                .await
                .expect("accept"),
            AcceptOutcome::Applied
        ));
        core.store
            .set_zone_cursor(&checkpoint(1_000))
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
            .accept_block(&genesis, checkpoint(1_000))
            .await
            .expect("accept");
        let block2 = common::test_utils::produce_dummy_block(2, Some(genesis.header.hash), vec![]);
        core.store
            .accept_block(&block2, checkpoint(1_005))
            .await
            .expect("accept");
        let block3 = common::test_utils::produce_dummy_block(3, Some(block2.header.hash), vec![]);
        core.store
            .accept_block(&block3, checkpoint(1_010))
            .await
            .expect("accept");

        // Cursor last persisted at the genesis slot: two blocks behind the tip.
        core.store
            .set_zone_cursor(&checkpoint(1_000))
            .expect("set cursor");

        let anchor = core.get_startup_anchor().expect("anchor").expect("present");
        let expected = Anchor::new(checkpoint(1_010), Some((3, block3.header.hash)));
        assert_eq!(anchor.slot(), expected.slot());
    }
}
