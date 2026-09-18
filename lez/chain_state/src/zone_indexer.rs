//! Temporary in-tree copy of the `ZoneIndexer` that zone-sdk removed in #3220.
//!
//! Kept verbatim so the sdk bump can be evaluated without also doing the
//! read-only-`ZoneSequencer` migration the removal asks for. Delete this
//! module once that migration lands.

use futures::{Stream, StreamExt as _};
use logos_blockchain_zone_sdk::{
    ZoneMessage, adapter,
    node_types::{ChannelId, Error as NodeError, Slot},
};

const BATCH_SIZE: Slot = Slot::new(100);

/// Indexer errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(#[from] NodeError),
}

/// Zone indexer — reads finalized zone messages from a channel.
pub struct ZoneIndexer<Node> {
    channel_id: ChannelId,
    node: Node,
}

impl<Node> ZoneIndexer<Node>
where
    Node: adapter::Node + Clone + Sync,
{
    #[must_use]
    pub const fn new(channel_id: ChannelId, node: Node) -> Self {
        Self { channel_id, node }
    }

    /// Subscribe to live [`ZoneMessage`]s as they finalize.
    pub async fn follow(&self) -> Result<impl Stream<Item = ZoneMessage> + '_, Error> {
        let lib_stream = self.node.lib_stream().await?;

        let channel_id = self.channel_id;
        let stream = lib_stream.filter_map(move |block_info| {
            let header_id = block_info.header_id;

            async move {
                let stream = match self
                    .node
                    .zone_messages_in_block(header_id, channel_id)
                    .await
                {
                    Ok(stream) => stream,
                    Err(e) => {
                        log::warn!("Failed to fetch LIB block {header_id}: {e}");
                        return None;
                    }
                };

                Some(stream)
            }
        });

        Ok(stream.flatten())
    }

    /// Stream finalized [`ZoneMessage`]s from `last_slot` (exclusive) up to
    /// LIB.
    ///
    /// `last_slot` is the last slot the caller has fully consumed. `None`
    /// means cold start — streaming begins from genesis. The caller is
    /// responsible for persisting `last_slot` only after the messages of that
    /// slot are durably processed; on crash before persist, restart with the
    /// previous cursor and re-process. Deposits/withdraws carry no `MsgId`,
    /// so this is the only safe resume point — a finer-grained cursor would
    /// either skip them or replay them inconsistently across restarts.
    pub async fn next_messages(
        &self,
        last_slot: Option<Slot>,
    ) -> Result<impl Stream<Item = (ZoneMessage, Slot)> + '_, Error> {
        let lib_slot = self.node.consensus_info().await?.cryptarchia_info.lib_slot;
        let start_slot = last_slot.map_or_else(Slot::genesis, |s| s.strict_add(1.into()));

        let stream = futures::stream::unfold(start_slot, move |current_slot| async move {
            if current_slot > lib_slot {
                return None;
            }

            let end_slot = (Slot::from(
                current_slot
                    .into_inner()
                    .saturating_add(BATCH_SIZE.into_inner())
                    .checked_sub(1)
                    .expect("slot shouldn't overflow"),
            ))
            .min(lib_slot);

            match self
                .node
                .zone_messages_in_blocks(current_slot, end_slot, self.channel_id)
                .await
            {
                Ok(messages) => Some((messages, end_slot.strict_add(1.into()))),
                Err(e) => {
                    log::warn!(
                        "Failed to fetch zone messages from blocks {current_slot:?}..={end_slot:?}: {e}",
                    );
                    None
                }
            }
        })
        .flatten();

        Ok(stream)
    }
}
