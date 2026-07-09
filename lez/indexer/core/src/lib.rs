use std::{path::Path, sync::Arc};

use anyhow::Result;
use arc_swap::ArcSwap;
use common::block::Block;
// TODO: Remove after testnet
use futures::StreamExt as _;
pub use ingest_error::BlockIngestError;
use log::{error, info, warn};
use logos_blockchain_zone_sdk::{
    CommonHttpClient, Slot, ZoneMessage, adapter::NodeHttpClient, indexer::ZoneIndexer,
};
use retry::ApplyRetryGate;
pub use stall_reason::StallReason;

use crate::{
    block_store::{AcceptOutcome, IndexerStore},
    chain_consistency::ChainConsistency,
    config::IndexerConfig,
    status::{IndexerStatus, IndexerSyncStatus},
};
pub mod block_store;
pub mod chain_consistency;
pub mod config;
pub mod ingest_error;
mod retry;
pub mod stall_reason;
pub mod status;

/// Consecutive failed apply attempts of the same block before parking.
const APPLY_RETRY_LIMIT: u32 = 3;

#[derive(Clone)]
pub struct IndexerCore {
    pub zone_indexer: Arc<ZoneIndexer<NodeHttpClient>>,
    /// Direct node handle for queries outside `ZoneIndexer`'s streaming API.
    pub node: NodeHttpClient,
    pub config: IndexerConfig,
    pub store: IndexerStore,
    /// Live ingestion status; updated by the ingest stream, read by `status`.
    pub status: Arc<ArcSwap<IndexerSyncStatus>>,
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

        Ok(Self {
            zone_indexer: Arc::new(zone_indexer),
            node,
            config,
            store: IndexerStore::open_db(&home)?,
            status: Arc::new(ArcSwap::from_pointee(IndexerSyncStatus::starting())),
        })
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
    fn advance_cursor(&self, cursor: &mut Option<Slot>, slot: Slot) {
        *cursor = Some(slot);
        if let Err(err) = self.store.set_zone_cursor(&slot) {
            warn!("Failed to persist indexer cursor: {err:#}");
        }
    }

    /// Parks on an inscription that could not be parsed as an L2 block:
    /// records the stall and flips the status. The validated tip stays frozen.
    fn park_undeserializable(&self, slot: Slot, error: std::io::Error) {
        let error = anyhow::Error::new(error);

        // use `:#` to get the entire error chain
        let reason = format!("{error:#}");
        error!("Failed to deserialize L2 block from zone-sdk: {reason}");
        if let Err(err) =
            self.store
                .record_stall(None, slot, BlockIngestError::Deserialize(reason.clone()))
        {
            warn!("Failed to record stall reason: {err:#}");
        }
        self.set_status(IndexerSyncStatus::stalled(format!(
            "failed to deserialize L2 block: {reason}"
        )));
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

            if cursor.is_some() {
                info!("Resuming indexer from cursor {cursor:?}");
            } else {
                info!("Starting indexer from beginning of channel");
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

                while let Some((msg, slot)) = stream.next().await {
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
                            self.park_undeserializable(slot, error);
                            // L1 proceeds regardless
                            self.advance_cursor(&mut cursor, slot);
                            continue;
                        }
                    };

                    match self.store.accept_block(&block, slot).await {
                        Ok(AcceptOutcome::Applied) => {
                            retry_gate.reset();
                            info!("Indexed L2 block {}", block.header.block_id);
                            self.set_status(IndexerSyncStatus::syncing());
                            self.advance_cursor(&mut cursor, slot);
                            yield Ok(block);
                        }
                        Ok(AcceptOutcome::AlreadyApplied) => {
                            info!(
                                "Skipping already-applied block {}",
                                block.header.block_id
                            );
                            self.advance_cursor(&mut cursor, slot);
                        }
                        Ok(AcceptOutcome::Parked(ingest_err)) => {
                            error!(
                                "Parked at block {}: {ingest_err}",
                                block.header.block_id
                            );
                            self.set_status(IndexerSyncStatus::stalled(ingest_err.to_string()));
                            // L1 proceeds regardless
                            self.advance_cursor(&mut cursor, slot);
                        }
                        Ok(AcceptOutcome::ApplyFailed(ingest_err)) => {
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
                                self.advance_cursor(&mut cursor, slot);
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
                    tokio::time::sleep(poll_interval).await;
                    continue;
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
