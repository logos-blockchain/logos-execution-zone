use std::{path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use arc_swap::ArcSwap;
use common::{HashType, block::Block};
// ToDo: Remove after testnet
use futures::StreamExt as _;
pub use ingest_error::BlockIngestError;
use lee::GENESIS_BLOCK_ID;
use log::{error, info, warn};
use logos_blockchain_zone_sdk::{
    CommonHttpClient, ZoneMessage, adapter::NodeHttpClient, indexer::ZoneIndexer,
};
pub use stall_reason::StallReason;

use crate::{
    block_store::{AcceptOutcome, IndexerStore},
    config::IndexerConfig,
    status::{IndexerStatus, IndexerSyncStatus},
};
pub mod block_store;
pub mod config;
pub mod ingest_error;
pub mod stall_reason;
pub mod status;

/// Result of comparing the indexer's stored genesis against the channel's.
enum GenesisOutcome {
    /// Match, or nothing to compare (fresh store / empty channel / L1 unreachable) — proceed.
    Consistent,
    /// The store holds a different chain than the channel now serves.
    Mismatch { stored: HashType, current: HashType },
}

#[derive(Clone)]
pub struct IndexerCore {
    pub zone_indexer: Arc<ZoneIndexer<NodeHttpClient>>,
    pub config: IndexerConfig,
    pub store: IndexerStore,
    /// Live ingestion status; updated by the ingest stream, read by `status`.
    pub status: Arc<ArcSwap<IndexerSyncStatus>>,
}

impl IndexerCore {
    pub fn new(config: IndexerConfig, storage_dir: &Path) -> Result<Self> {
        // Namespace the DB by channel so indexers on different channels can
        // share a storage dir without their RocksDB state colliding.
        let home = storage_dir.join(format!("rocksdb-{}", config.channel_id));

        let basic_auth = config.bedrock_config.auth.clone().map(Into::into);
        let node = NodeHttpClient::new(
            CommonHttpClient::new(basic_auth),
            config.bedrock_config.addr.clone(),
        );
        let zone_indexer = ZoneIndexer::new(config.channel_id, node);

        Ok(Self {
            zone_indexer: Arc::new(zone_indexer),
            config,
            store: IndexerStore::open_db(&home)?,
            status: Arc::new(ArcSwap::from_pointee(IndexerSyncStatus::starting())),
        })
    }

    /// Builds the core, then verifies the stored genesis matches the channel's.
    /// On mismatch: refuse (error) unless `allow_reset`, in which case wipe the store
    /// and re-index from scratch. Used at service/FFI startup in place of `new`.
    pub async fn new_with_genesis_check(
        config: IndexerConfig,
        storage_dir: &Path,
        allow_reset: bool,
    ) -> Result<Self> {
        let home = storage_dir.join(format!("rocksdb-{}", config.channel_id));
        let core = Self::new(config.clone(), storage_dir)?;
        match core.genesis_outcome().await? {
            GenesisOutcome::Consistent => Ok(core),
            GenesisOutcome::Mismatch { stored, current } if allow_reset => {
                warn!(
                    "Chain reset detected: stored genesis {stored} != channel genesis {current}. \
                     Wiping indexer store at {} and re-indexing.",
                    home.display()
                );
                drop(core); // sole owner before the ingest task is spawned → closes the DB
                storage::indexer::RocksDBIO::destroy(&home)?;
                Self::new(config, storage_dir)
            }
            GenesisOutcome::Mismatch { stored, current } => Err(anyhow::anyhow!(
                "Indexer store at {} holds a different chain than the channel now serves \
                 (stored genesis {stored} != channel genesis {current}). Run `just clean`, \
                 point at a fresh storage dir, or set `allow_chain_reset` in the indexer config.",
                home.display()
            )),
        }
    }

    /// Compares the stored genesis (block 1) against the channel's current genesis.
    async fn genesis_outcome(&self) -> Result<GenesisOutcome> {
        let stored = self.store.get_block_at_id(GENESIS_BLOCK_ID)?;
        if stored.is_none() {
            return Ok(GenesisOutcome::Consistent); // fresh store: skip the L1 read entirely
        }
        let current = self.fetch_channel_genesis().await?;
        Ok(compare_genesis(stored.as_ref(), current.as_ref()))
    }

    /// Reads the channel's genesis (first `Block`) from the start of the channel.
    /// Returns `None` if the channel has no block yet or L1 can't be reached within
    /// the timeout — the check is best-effort and must never block or fail startup.
    async fn fetch_channel_genesis(&self) -> Result<Option<Block>> {
        const GENESIS_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
        let fetch = async {
            let stream = self.zone_indexer.next_messages(None).await?;
            let mut stream = std::pin::pin!(stream);
            while let Some((msg, _slot)) = stream.next().await {
                if let ZoneMessage::Block(zone_block) = msg {
                    let block: Block = borsh::from_slice(&zone_block.data)
                        .context("Failed to deserialize channel genesis block")?;
                    return Ok::<Option<Block>, anyhow::Error>(Some(block));
                }
            }
            Ok(None)
        };
        match tokio::time::timeout(GENESIS_FETCH_TIMEOUT, fetch).await {
            Ok(res) => res,
            Err(_elapsed) => {
                warn!("Timed out reading channel genesis for the consistency check; proceeding");
                Ok(None)
            }
        }
    }

    /// Snapshot of the current ingestion status (sync state + indexed tip).
    ///
    /// Combines the ingest loop's live status with the L2 tip read fresh from the
    /// store, so callers (FFI/RPC) can tell "catching up" from "failed".
    #[must_use]
    pub fn status(&self) -> IndexerStatus {
        let sync = IndexerSyncStatus::clone(&self.status.load());
        let indexed_block_id = self.store.get_last_block_id().ok().flatten();
        let stall_reason = self.store.get_stall_reason().ok().flatten();
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

    pub fn subscribe_parse_block_stream(&self) -> impl futures::Stream<Item = Result<Block>> + '_ {
        let poll_interval = self.config.consensus_info_polling_interval;
        let initial_cursor = self
            .store
            .get_zone_cursor()
            .expect("Failed to load zone-sdk indexer cursor");

        async_stream::stream! {
            let mut cursor = initial_cursor;

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
                        ZoneMessage::Deposit(_) | ZoneMessage::Withdraw(_) => continue,
                    };

                    let l1_slot = serde_json::to_value(slot).unwrap_or(serde_json::Value::Null);

                    let block: Block = match borsh::from_slice(&zone_block.data) {
                        Ok(b) => b,
                        Err(e) => {
                            error!("Failed to deserialize L2 block from zone-sdk: {e}");
                            if let Err(err) =
                                self.store.record_deserialize_stall(l1_slot, e.to_string())
                            {
                                warn!("Failed to record stall reason: {err:#}");
                            }
                            self.set_status(IndexerSyncStatus::stalled(format!(
                                "failed to deserialize L2 block: {e}"
                            )));
                            // Advance the L1 read cursor past the broken inscription;
                            // the validated tip stays frozen.
                            cursor = Some(slot);
                            if let Err(err) = self.store.set_zone_cursor(&slot) {
                                warn!("Failed to persist indexer cursor: {err:#}");
                            }
                            continue;
                        }
                    };

                    match self.store.accept_block(&block, l1_slot).await {
                        Ok(AcceptOutcome::Applied) => {
                            info!("Indexed L2 block {}", block.header.block_id);
                            self.set_status(IndexerSyncStatus::syncing());
                            cursor = Some(slot);
                            if let Err(err) = self.store.set_zone_cursor(&slot) {
                                warn!("Failed to persist indexer cursor: {err:#}");
                            }
                            yield Ok(block);
                        }
                        Ok(AcceptOutcome::Parked(ingest_err)) => {
                            error!(
                                "Parked at block {}: {ingest_err}",
                                block.header.block_id
                            );
                            self.set_status(IndexerSyncStatus::stalled(ingest_err.to_string()));
                            // Advance the L1 read cursor; tip stays frozen, no yield.
                            cursor = Some(slot);
                            if let Err(err) = self.store.set_zone_cursor(&slot) {
                                warn!("Failed to persist indexer cursor: {err:#}");
                            }
                        }
                        Err(err) => {
                            // Infrastructure error (DB read/write), not a bad block.
                            // Keep the cursor put; re-poll the same position next cycle.
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
                if self.store.get_stall_reason().ok().flatten().is_none() {
                    self.set_status(IndexerSyncStatus::caught_up());
                }
                tokio::time::sleep(poll_interval).await;
            }
        }
    }
}

/// Pure comparison: a mismatch requires BOTH a stored and a channel genesis whose
/// hashes differ; any missing side is treated as Consistent (nothing to act on).
fn compare_genesis(stored: Option<&Block>, current: Option<&Block>) -> GenesisOutcome {
    match (stored, current) {
        (Some(s), Some(c)) if s.header.hash != c.header.hash => GenesisOutcome::Mismatch {
            stored: s.header.hash,
            current: c.header.hash,
        },
        _ => GenesisOutcome::Consistent,
    }
}

#[cfg(test)]
mod genesis_check_tests {
    use common::{HashType, block::Block, test_utils::produce_dummy_block};

    use super::{GenesisOutcome, compare_genesis};

    fn genesis_with_prev(prev_seed: u8) -> Block {
        produce_dummy_block(1, Some(HashType([prev_seed; 32])), vec![])
    }

    #[test]
    fn matching_genesis_is_consistent() {
        let g = genesis_with_prev(1);
        assert!(matches!(
            compare_genesis(Some(&g), Some(&g)),
            GenesisOutcome::Consistent
        ));
    }

    #[test]
    fn differing_genesis_is_mismatch() {
        let stored = genesis_with_prev(1);
        let current = genesis_with_prev(2);
        assert!(matches!(
            compare_genesis(Some(&stored), Some(&current)),
            GenesisOutcome::Mismatch { .. }
        ));
    }

    #[test]
    fn missing_either_side_is_consistent() {
        let g = genesis_with_prev(1);
        assert!(matches!(
            compare_genesis(None, Some(&g)),
            GenesisOutcome::Consistent
        ));
        assert!(matches!(
            compare_genesis(Some(&g), None),
            GenesisOutcome::Consistent
        ));
        assert!(matches!(
            compare_genesis(None, None),
            GenesisOutcome::Consistent
        ));
    }
}
