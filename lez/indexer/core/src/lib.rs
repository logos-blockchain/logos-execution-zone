use std::{path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use arc_swap::ArcSwap;
use common::block::Block;
// TODO: Remove after testnet
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

/// First post-genesis L2 block.
///
/// We use this to differentiate between a local rocksdb chain
/// and the connected chain, to see if we should reset (mostly dev purposes).
/// While such a discrepancy will not happen during live-chain indexing, this
/// saves us some trouble during development (especially when used within UI
/// with the indexer module).
///
/// Genesis is deterministic so it is byte-identical across chains, so instead
/// we use the second block to differentiate between chains.
const ANCHOR_BLOCK_ID: u64 = GENESIS_BLOCK_ID + 1;

/// Result of comparing the indexer's stored anchor block against the channel's.
enum ChainIdentityOutcome {
    /// One of the following possibilities:
    /// - Anchors match
    /// - Nothing to compare (store has only genesis)
    /// - L1 was unreadable (proceed from the persisted cursor; fail-over)
    Consistent,
    /// The store holds a different chain than the channel now serves; `detail`
    /// describes how (differing anchor, or the channel lacks the anchor entirely).
    Mismatch { detail: String },
}

/// Outcome of reading the channel's anchor block at startup.
enum AnchorRead {
    /// The channel's anchor block.
    Found(Block),
    /// The channel definitively has no anchor (drained up to LIB without it).
    /// Since our stored anchor was finalized, a finalized channel that lacks it is
    /// a different chain.
    Absent,
    /// Could not read the channel in time (slow/unreachable L1) — best-effort skip.
    Unreadable,
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

    /// Builds the core, then verifies the stored chain matches the channel's by
    /// comparing the anchor block (id 2 — genesis is identical across chains, so
    /// it can't detect a reset). On mismatch: refuse (error) unless `allow_reset`,
    /// in which case wipe the store and re-index from scratch. Used at service/FFI
    /// startup in place of `new`.
    pub async fn new_with_chain_check(
        config: IndexerConfig,
        storage_dir: &Path,
        allow_reset: bool,
    ) -> Result<Self> {
        let home = storage_dir.join(format!("rocksdb-{}", config.channel_id));
        let core = Self::new(config.clone(), storage_dir)?;
        match core.chain_identity_outcome().await? {
            ChainIdentityOutcome::Consistent => Ok(core),
            ChainIdentityOutcome::Mismatch { detail } if allow_reset => {
                warn!(
                    "Chain reset detected ({detail}). Wiping indexer store at {} and re-indexing.",
                    home.display()
                );
                drop(core); // sole owner before the ingest task is spawned → closes the DB
                storage::indexer::RocksDBIO::destroy(&home)?;
                Self::new(config, storage_dir)
            }
            ChainIdentityOutcome::Mismatch { detail } => Err(anyhow::anyhow!(
                "Indexer store at {} holds a different chain than the channel now serves \
                 ({detail}). Run `just clean`, point at a fresh storage dir, or set \
                 `allow_chain_reset` in the indexer config.",
                home.display()
            )),
        }
    }

    /// Compares the stored anchor block (id 2) against the channel's current one.
    /// An absent channel anchor means a different (shorter) chain, since our stored
    /// anchor was finalized and finalized history does not shrink on the same chain.
    async fn chain_identity_outcome(&self) -> Result<ChainIdentityOutcome> {
        let Some(stored) = self.store.get_block_at_id(ANCHOR_BLOCK_ID)? else {
            // Store has at most genesis: nothing post-genesis to compare against.
            return Ok(ChainIdentityOutcome::Consistent);
        };
        Ok(match self.fetch_channel_anchor().await? {
            AnchorRead::Found(current) => compare_anchor(&stored, &current),
            AnchorRead::Absent => ChainIdentityOutcome::Mismatch {
                detail: format!(
                    "channel serves no block {ANCHOR_BLOCK_ID}, but the store holds anchor {}",
                    stored.header.hash
                ),
            },
            AnchorRead::Unreadable => ChainIdentityOutcome::Consistent,
        })
    }

    /// Reads the channel's anchor block (first `Block` with id [`ANCHOR_BLOCK_ID`])
    /// from the start of the channel.
    ///
    /// Bedrock can be slow to serve the channel right after boot, so we allow a
    /// generous timeout. `Unreadable` on error/timeout keeps startup best-effort
    /// (never refuse on a transient L1 hiccup); `Absent` means the channel has no
    /// anchor in its finalized history, which the caller treats as a reset.
    async fn fetch_channel_anchor(&self) -> Result<AnchorRead> {
        const ANCHOR_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);
        let fetch = async {
            let stream = self.zone_indexer.next_messages(None).await?;
            let mut stream = std::pin::pin!(stream);
            while let Some((msg, _slot)) = stream.next().await {
                let ZoneMessage::Block(zone_block) = msg else {
                    continue;
                };
                let block: Block = borsh::from_slice(&zone_block.data)
                    .context("Failed to deserialize channel block")?;
                if block.header.block_id == ANCHOR_BLOCK_ID {
                    return Ok::<AnchorRead, anyhow::Error>(AnchorRead::Found(block));
                }
                if block.header.block_id > ANCHOR_BLOCK_ID {
                    break; // blocks arrive in order: we passed the anchor without seeing it
                }
            }
            Ok(AnchorRead::Absent)
        };
        match tokio::time::timeout(ANCHOR_FETCH_TIMEOUT, fetch).await {
            Ok(Ok(read)) => Ok(read),
            Ok(Err(err)) => {
                warn!(
                    "Failed to read channel anchor for the consistency check; proceeding: {err:#}"
                );
                Ok(AnchorRead::Unreadable)
            }
            Err(_elapsed) => {
                warn!("Timed out reading channel anchor for the consistency check; proceeding");
                Ok(AnchorRead::Unreadable)
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

/// Pure comparison of two anchor blocks: a mismatch is differing hashes. The
/// missing-side cases are handled upstream (`Absent`/`Unreadable`).
fn compare_anchor(stored: &Block, current: &Block) -> ChainIdentityOutcome {
    if stored.header.hash == current.header.hash {
        ChainIdentityOutcome::Consistent
    } else {
        ChainIdentityOutcome::Mismatch {
            detail: format!(
                "stored anchor {} != channel anchor {}",
                stored.header.hash, current.header.hash
            ),
        }
    }
}

#[cfg(test)]
mod chain_identity_tests {
    use common::{HashType, block::Block, test_utils::produce_dummy_block};

    use super::{ANCHOR_BLOCK_ID, ChainIdentityOutcome, compare_anchor};

    fn anchor_with_prev(prev_seed: u8) -> Block {
        produce_dummy_block(ANCHOR_BLOCK_ID, Some(HashType([prev_seed; 32])), vec![])
    }

    #[test]
    fn matching_anchor_is_consistent() {
        let a = anchor_with_prev(1);
        assert!(matches!(
            compare_anchor(&a, &a),
            ChainIdentityOutcome::Consistent
        ));
    }

    #[test]
    fn differing_anchor_is_mismatch() {
        let stored = anchor_with_prev(1);
        let current = anchor_with_prev(2);
        assert!(matches!(
            compare_anchor(&stored, &current),
            ChainIdentityOutcome::Mismatch { .. }
        ));
    }
}
