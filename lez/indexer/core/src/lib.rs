use std::{path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use arc_swap::ArcSwap;
use common::block::Block;
// TODO: Remove after testnet
use futures::StreamExt as _;
pub use ingest_error::BlockIngestError;
use log::{error, info, warn};
use logos_blockchain_zone_sdk::{
    CommonHttpClient, Slot, ZoneMessage, adapter::NodeHttpClient, indexer::ZoneIndexer,
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

/// Result of comparing the indexer's stored tip against the channel.
enum ChainIdentityOutcome {
    /// Proceed from the cursor: channel still serves our chain, nothing to compare,
    /// or the check was inconclusive — none of which prove a reset.
    Consistent,
    /// The channel serves a different block at one of our ids — a chain reset.
    Mismatch { detail: String },
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
    /// re-reading the channel at the stored tip's position. On mismatch: refuse
    /// (error) unless `allow_reset`, in which case wipe the store and re-index from
    /// scratch. Used at service/FFI startup in place of `new`.
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

    /// Detects when the local store belongs to a different chain than the connected L1
    /// (e.g. a wiped/restarted bedrock) so startup can reset instead of silently
    /// diverging. Mostly a dev convenience; won't trigger during normal live indexing.
    ///
    /// Compares the first block the channel serves at/after the cursor (the tip's
    /// recent L1 slot, so ~one batch — not a from-genesis scan) against our stored
    /// block of the *same id*. Comparing by the channel's id, not our tip id, is what
    /// catches a *shorter* reset chain: it has no block at our tip id, but its low-id
    /// block here differs from ours.
    async fn chain_identity_outcome(&self) -> Result<ChainIdentityOutcome> {
        // Don't skip parked stores: the stall is persisted and only clears on a
        // successful apply, so skipping would re-park forever and never catch a reset.
        // Safe anyway — a same-chain park sits at an id we never applied, so the lookup
        // below misses → Consistent.
        let Some(cursor) = self.store.get_zone_cursor()? else {
            return Ok(ChainIdentityOutcome::Consistent); // empty / cold store
        };

        // Inconclusive cases stay Consistent (ingest parks if truly divergent) rather
        // than wipe a valid store: empty/unreadable read (notably bedrock's LIB behind
        // our tip), or an id we don't hold. Blind spot: a genesis-only store can't be
        // told apart (genesis is deterministic), but that window is transient.
        let Some(channel_block) = self.fetch_channel_block_from(cursor).await? else {
            return Ok(ChainIdentityOutcome::Consistent);
        };
        let Some(ours) = self.store.get_block_at_id(channel_block.header.block_id)? else {
            return Ok(ChainIdentityOutcome::Consistent);
        };
        Ok(compare_block(&ours, &channel_block))
    }

    /// Reads the first block the channel serves at/after the tip's slot. `next_messages`
    /// is exclusive, so `cursor - 1` includes the tip's own slot. `None` = inconclusive
    /// (timeout/error, or bedrock's LIB behind our tip → empty stream).
    async fn fetch_channel_block_from(&self, cursor: Slot) -> Result<Option<Block>> {
        const TIP_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
        // Slot-0 cursor is degenerate (inscriptions live at wall-clock slots); bail
        // rather than let `next_messages(None)` do a from-genesis scan.
        let Some(from_slot) = cursor.into_inner().checked_sub(1) else {
            return Ok(None);
        };
        let fetch = async {
            let stream = self
                .zone_indexer
                .next_messages(Some(Slot::from(from_slot)))
                .await?;
            let mut stream = std::pin::pin!(stream);
            while let Some((msg, _slot)) = stream.next().await {
                if let ZoneMessage::Block(zone_block) = msg {
                    let block: Block = borsh::from_slice(&zone_block.data)
                        .context("Failed to deserialize channel block")?;
                    return Ok::<Option<Block>, anyhow::Error>(Some(block));
                }
            }
            Ok(None)
        };
        match tokio::time::timeout(TIP_FETCH_TIMEOUT, fetch).await {
            Ok(Ok(found)) => Ok(found),
            Ok(Err(err)) => {
                warn!("Failed to read channel tip for the consistency check; proceeding: {err:#}");
                Ok(None)
            }
            Err(_elapsed) => {
                warn!("Timed out reading channel tip for the consistency check; proceeding");
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
                        Ok(AcceptOutcome::AlreadyApplied) => {
                            info!(
                                "Skipping already-applied block {}",
                                block.header.block_id
                            );
                            cursor = Some(slot);
                            if let Err(err) = self.store.set_zone_cursor(&slot) {
                                warn!("Failed to persist indexer cursor: {err:#}");
                            }
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

/// Pure comparison of our stored block against the channel's block at the same id:
/// a mismatch is differing hashes. Missing/unreadable cases are handled upstream.
fn compare_block(ours: &Block, channel: &Block) -> ChainIdentityOutcome {
    if ours.header.hash == channel.header.hash {
        ChainIdentityOutcome::Consistent
    } else {
        ChainIdentityOutcome::Mismatch {
            detail: format!(
                "stored block {} {} != channel block {} {}",
                ours.header.block_id,
                ours.header.hash,
                channel.header.block_id,
                channel.header.hash
            ),
        }
    }
}

#[cfg(test)]
mod chain_identity_tests {
    use common::{HashType, block::Block, test_utils::produce_dummy_block};

    use super::{ChainIdentityOutcome, compare_block};

    fn block_with_prev(prev_seed: u8) -> Block {
        produce_dummy_block(5, Some(HashType([prev_seed; 32])), vec![])
    }

    #[test]
    fn matching_block_is_consistent() {
        let b = block_with_prev(1);
        assert!(matches!(
            compare_block(&b, &b),
            ChainIdentityOutcome::Consistent
        ));
    }

    #[test]
    fn differing_block_is_mismatch() {
        let stored = block_with_prev(1);
        let current = block_with_prev(2);
        assert!(matches!(
            compare_block(&stored, &current),
            ChainIdentityOutcome::Mismatch { .. }
        ));
    }
}
