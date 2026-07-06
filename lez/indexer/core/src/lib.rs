use std::{path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use arc_swap::ArcSwap;
use common::{HashType, block::Block};
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
enum ChainConsistenty {
    /// Channel serves the same block at our tip's id.
    Consistent,
    /// We could not determine the outcome due to one of:
    ///
    /// - cold store
    /// - the channel served no comparable block, we hold no block at that id
    /// - or the channel read was inconclusive (timeout / error / empty stream)
    ///
    /// NOTE: None of these prove a reset, so the caller proceeds.
    /// A genuine divergence is still caught later when the ingest loop tries to apply and parks.
    Inconclusive,
    /// The channel serves a different block at one of our ids.
    ///
    /// Details in [`BlockMismatch`], and impl's Display trait.
    Inconsistent(BlockMismatch),
}

/// The differing pair behind a [`ChainConsistenty::Inconsistent`]: our stored
/// block vs. the block the channel serves at the same id, as `(block_id, hash)`.
struct BlockMismatch {
    ours: (u64, HashType),
    channel: (u64, HashType),
}

impl std::fmt::Display for BlockMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { ours, channel } = self;
        write!(
            f,
            "stored block {} {} != channel block {} {}",
            ours.0, ours.1, channel.0, channel.1
        )
    }
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
            ChainConsistenty::Consistent | ChainConsistenty::Inconclusive => Ok(core),
            ChainConsistenty::Inconsistent(mismatch) if config.allow_chain_reset => {
                warn!(
                    "Chain reset detected ({mismatch}). Wiping indexer store at {} and \
                     re-indexing.",
                    home.display()
                );
                drop(core); // sole owner before the ingest task is spawned → closes the DB
                storage::indexer::RocksDBIO::destroy(&home)?;
                Self::open(config, storage_dir)
            }
            ChainConsistenty::Inconsistent(mismatch) => Err(anyhow::anyhow!(
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
        let zone_indexer = ZoneIndexer::new(config.channel_id, node);

        Ok(Self {
            zone_indexer: Arc::new(zone_indexer),
            config,
            store: IndexerStore::open_db(&home)?,
            status: Arc::new(ArcSwap::from_pointee(IndexerSyncStatus::starting())),
        })
    }

    /// Detects when the local store belongs to a different chain than the connected L1
    /// (e.g. a wiped/restarted bedrock) so startup can reset instead of silently
    /// diverging. Mostly a dev convenience; won't trigger during normal live indexing.
    ///
    /// Compares the **first** block the channel serves at/after the cursor (the tip's
    /// recent L1 slot) against our stored block of the *same id*.
    /// Note that we have to respect the channel's tip slot, because if our tip
    /// is ahead of the channel even in the same chain, it may looks like we are
    /// ahead of the channel, but we are actually on a different chain.
    async fn verify_chain_consistency(&self) -> Result<ChainConsistenty> {
        let Some(cursor) = self.store.get_zone_cursor()? else {
            // if we have no cursor, the store is empty or cold: nothing to compare
            return Ok(ChainConsistenty::Inconclusive);
        };

        let Some(channel) = self.fetch_channel_block_from(cursor).await? else {
            // if the channel is empty, we have nothing to compare
            return Ok(ChainConsistenty::Inconclusive);
        };

        let Some(ours) = self.store.get_block_at_id(channel.header.block_id)? else {
            // if we do not have the block the channel serves at that id, we cannot compare
            return Ok(ChainConsistenty::Inconclusive);
        };

        // copare the block w.r.t hashes
        let comparison_result = if ours.header.hash == channel.header.hash {
            ChainConsistenty::Consistent
        } else {
            ChainConsistenty::Inconsistent(BlockMismatch {
                ours: (ours.header.block_id, ours.header.hash),
                channel: (channel.header.block_id, channel.header.hash),
            })
        };

        Ok(comparison_result)
    }

    /// Reads the first block the channel serves at/after the tip's slot.
    ///
    /// `None` means we could not read a comparable block.
    async fn fetch_channel_block_from(&self, cursor: Slot) -> Result<Option<Block>> {
        const TIP_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

        // `next_messages` is exclusive, so `cursor - 1` includes the tip's own slot.
        let Some(from_slot) = cursor.into_inner().checked_sub(1) else {
            // Slot-0 cursor is degenerate (inscriptions live at wall-clock slots);
            // so we bail rather than let `next_messages(None)` do a from-genesis scan.
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

#[cfg(test)]
mod chain_identity_tests {
    use std::time::Duration;

    use super::{ChainConsistenty, IndexerCore};
    use crate::config::{ChannelId, ClientConfig, IndexerConfig};

    #[tokio::test]
    async fn cold_store_is_inconclusive() {
        // An empty store has no cursor, so there is nothing to compare: the check
        // must be Inconclusive (not Consistent), and it returns before any L1 read.
        let dir = tempfile::tempdir().expect("tempdir");
        let config = IndexerConfig {
            consensus_info_polling_interval: Duration::from_secs(1),
            bedrock_config: ClientConfig {
                addr: "http://localhost:1".parse().expect("url"),
                auth: None,
            },
            channel_id: ChannelId::from([1; 32]),
            allow_chain_reset: false,
        };
        let core = IndexerCore::open(config, dir.path()).expect("open core");
        assert!(matches!(
            core.verify_chain_consistency().await.expect("verify"),
            ChainConsistenty::Inconclusive
        ));
    }
}
