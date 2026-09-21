//! Temporary in-tree copy of the `ZoneIndexer` that zone-sdk removed in #3220.
//!
//! Kept verbatim so the sdk bump can be evaluated without also doing the
//! read-only-`ZoneSequencer` migration the removal asks for. Delete this
//! module once that migration lands.

use futures::{Stream, StreamExt as _, future::Either};
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
    // `cause` rather than `source`: every caller prints this with plain `Display`,
    // so the reason has to be in the message rather than in a source chain.
    #[error("failed to fetch zone messages from blocks {from:?}..={to:?}: {cause}")]
    Fetch {
        from: Slot,
        to: Slot,
        cause: NodeError,
    },
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
    ///
    /// A failed batch is an `Err` item; ending the stream means "reached LIB".
    pub async fn next_messages(
        &self,
        last_slot: Option<Slot>,
    ) -> Result<impl Stream<Item = Result<(ZoneMessage, Slot), Error>> + '_, Error> {
        let lib_slot = self.node.consensus_info().await?.cryptarchia_info.lib_slot;
        let start_slot = last_slot.map_or_else(Slot::genesis, |s| s.strict_add(1.into()));

        let stream = futures::stream::unfold(Some(start_slot), move |next| async move {
            let current_slot = next?;
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
                Ok(messages) => Some((
                    Either::Left(messages.map(Ok)),
                    Some(end_slot.strict_add(1.into())),
                )),
                Err(cause) => Some((
                    Either::Right(futures::stream::once(std::future::ready(Err(
                        Error::Fetch {
                            from: current_slot,
                            to: end_slot,
                            cause,
                        },
                    )))),
                    None,
                )),
            }
        })
        .flatten();

        Ok(stream)
    }
}

/// Ends the pass at the first read failure, naming `what` failed. For callers that
/// retry the pass; wrong for one that concludes a scan is complete when it ends.
pub fn stop_at_read_error<'stream, S>(
    stream: S,
    what: String,
) -> impl Stream<Item = (ZoneMessage, Slot)> + 'stream
where
    S: Stream<Item = Result<(ZoneMessage, Slot), Error>> + 'stream,
{
    stream
        .take_while(move |item| {
            let keep = match item {
                Ok(_) => true,
                Err(err) => {
                    log::warn!("{what}: {err}");
                    false
                }
            };
            std::future::ready(keep)
        })
        .filter_map(|item| std::future::ready(item.ok()))
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use futures::StreamExt as _;
    use logos_blockchain_zone_sdk::{
        ZoneBlock,
        node_types::{
            ApiBlock, BlockInfo, ChainServiceInfo, ChannelState, Events, HeaderId, Inscription,
            MsgId, ProcessedBlockEvent, SignedMantleTx, TimeInfo, Unverified,
            WalletFundRequestBody, WalletFundResponseBody,
        },
    };

    use super::{
        BATCH_SIZE, ChannelId, Error, NodeError, Slot, ZoneIndexer, ZoneMessage, adapter,
        stop_at_read_error,
    };

    /// `lib_slot` far enough ahead that at least one batch is attempted.
    const CONSENSUS_INFO: &str = r#"{
        "cryptarchia_info": {
            "lib": "a93e640f708786581412d58397db59e0a41e6cf839f09ea50079f2a876e216f3",
            "lib_slot": 500,
            "tip": "a93e640f708786581412d58397db59e0a41e6cf839f09ea50079f2a876e216f3",
            "slot": 500,
            "height": 1,
            "state": "Online"
        },
        "phase": "Following"
    }"#;

    /// Reachable for `consensus_info`, failing for every batch read.
    #[derive(Clone)]
    struct UnreadableNode;

    #[async_trait]
    impl adapter::Node for UnreadableNode {
        async fn consensus_info(&self) -> Result<ChainServiceInfo, NodeError> {
            Ok(serde_json::from_str(CONSENSUS_INFO)
                .expect("the fixture matches the node's wire shape"))
        }

        async fn immutable_blocks(
            &self,
            _slot_from: Slot,
            _slot_to: Slot,
        ) -> Result<Vec<ApiBlock>, NodeError> {
            Err(NodeError::Client("node down".to_owned()))
        }

        async fn time_info(&self) -> Result<TimeInfo, NodeError> {
            unreachable!()
        }

        async fn channel_state(
            &self,
            _channel_id: ChannelId,
        ) -> Result<Option<ChannelState>, NodeError> {
            unreachable!()
        }

        async fn block_stream(&self) -> Result<adapter::BoxStream<ProcessedBlockEvent>, NodeError> {
            unreachable!()
        }

        async fn lib_stream(&self) -> Result<adapter::BoxStream<BlockInfo>, NodeError> {
            unreachable!()
        }

        async fn block(&self, _id: HeaderId) -> Result<Option<ApiBlock>, NodeError> {
            unreachable!()
        }

        async fn block_events(&self, _id: HeaderId) -> Result<Option<Events>, NodeError> {
            unreachable!()
        }

        async fn post_transaction(&self, _tx: SignedMantleTx<Unverified>) -> Result<(), NodeError> {
            unreachable!()
        }

        async fn fund_tx(
            &self,
            _request: WalletFundRequestBody,
        ) -> Result<WalletFundResponseBody, NodeError> {
            unreachable!()
        }
    }

    /// Serves one message per batch, failing once `serve_batches` are gone.
    #[derive(Clone)]
    struct ScriptedNode {
        serve_batches: Option<usize>,
        served: Arc<AtomicUsize>,
    }

    impl ScriptedNode {
        fn always_serving() -> Self {
            Self {
                serve_batches: None,
                served: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn serving_one_batch() -> Self {
            Self {
                serve_batches: Some(1),
                served: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait]
    impl adapter::Node for ScriptedNode {
        async fn consensus_info(&self) -> Result<ChainServiceInfo, NodeError> {
            Ok(serde_json::from_str(CONSENSUS_INFO)
                .expect("the fixture matches the node's wire shape"))
        }

        async fn zone_messages_in_blocks(
            &self,
            slot_from: Slot,
            _slot_to: Slot,
            _channel_id: ChannelId,
        ) -> Result<adapter::BoxStream<(ZoneMessage, Slot)>, NodeError> {
            let served = self.served.fetch_add(1, Ordering::Relaxed);
            if self.serve_batches.is_some_and(|limit| served >= limit) {
                return Err(NodeError::Client("node down".to_owned()));
            }
            Ok(Box::pin(futures::stream::iter(vec![(
                message(0),
                slot_from,
            )])))
        }

        async fn immutable_blocks(
            &self,
            _slot_from: Slot,
            _slot_to: Slot,
        ) -> Result<Vec<ApiBlock>, NodeError> {
            unreachable!()
        }

        async fn time_info(&self) -> Result<TimeInfo, NodeError> {
            unreachable!()
        }

        async fn channel_state(
            &self,
            _channel_id: ChannelId,
        ) -> Result<Option<ChannelState>, NodeError> {
            unreachable!()
        }

        async fn block_stream(&self) -> Result<adapter::BoxStream<ProcessedBlockEvent>, NodeError> {
            unreachable!()
        }

        async fn lib_stream(&self) -> Result<adapter::BoxStream<BlockInfo>, NodeError> {
            unreachable!()
        }

        async fn block(&self, _id: HeaderId) -> Result<Option<ApiBlock>, NodeError> {
            unreachable!()
        }

        async fn block_events(&self, _id: HeaderId) -> Result<Option<Events>, NodeError> {
            unreachable!()
        }

        async fn post_transaction(&self, _tx: SignedMantleTx<Unverified>) -> Result<(), NodeError> {
            unreachable!()
        }

        async fn fund_tx(
            &self,
            _request: WalletFundRequestBody,
        ) -> Result<WalletFundResponseBody, NodeError> {
            unreachable!()
        }
    }

    fn channel_id() -> ChannelId {
        ChannelId::from([1_u8; 32])
    }

    fn message(tag: u8) -> ZoneMessage {
        ZoneMessage::Block(ZoneBlock {
            id: MsgId::root(),
            data: Inscription::try_from(vec![tag]).expect("one byte is under the inscription cap"),
        })
    }

    #[tokio::test]
    async fn a_failed_read_is_an_error_item_not_the_end_of_the_stream() {
        let indexer = ZoneIndexer::new(channel_id(), UnreadableNode);
        let stream = indexer
            .next_messages(None)
            .await
            .expect("consensus_info is reachable");

        let items: Vec<_> = stream.collect().await;

        assert!(
            matches!(items.as_slice(), [Err(Error::Fetch { .. })]),
            "one failure, reported as an item: {items:?}"
        );
    }

    #[tokio::test]
    async fn the_error_carries_the_range_that_was_not_read() {
        let indexer = ZoneIndexer::new(channel_id(), UnreadableNode);
        let stream = indexer
            .next_messages(None)
            .await
            .expect("consensus_info is reachable");

        let items: Vec<_> = stream.collect().await;

        let Some(Err(Error::Fetch { from, to, .. })) = items.first() else {
            panic!("expected a fetch error: {items:?}");
        };
        assert_eq!(*from, Slot::genesis(), "a cold start reads from genesis");
        assert_eq!(
            *to,
            Slot::from(BATCH_SIZE.into_inner().saturating_sub(1)),
            "the first batch spans BATCH_SIZE slots"
        );
    }

    #[tokio::test]
    async fn stop_at_read_error_truncates_at_the_failure() {
        let scripted = futures::stream::iter(vec![
            Ok((message(1), Slot::genesis())),
            Err(Error::Fetch {
                from: Slot::from(100),
                to: Slot::from(199),
                cause: NodeError::Client("node down".to_owned()),
            }),
            Ok((message(2), Slot::from(200))),
        ]);

        let delivered: Vec<_> = stop_at_read_error(scripted, "test read".to_owned())
            .collect()
            .await;

        assert_eq!(
            delivered,
            vec![(message(1), Slot::genesis())],
            "everything up to the failure, nothing past it"
        );
    }

    #[tokio::test]
    async fn batches_advance_and_end_at_lib_slot() {
        let indexer = ZoneIndexer::new(channel_id(), ScriptedNode::always_serving());
        let stream = indexer
            .next_messages(None)
            .await
            .expect("consensus_info is reachable");

        let items: Vec<_> = stream.collect().await;

        let slots: Vec<_> = items
            .into_iter()
            .map(|item| item.expect("every batch serves").1)
            .collect();
        assert_eq!(
            slots,
            [0, 100, 200, 300, 400, 500].map(Slot::from).to_vec(),
            "one message per batch, batches contiguous and ending at LIB"
        );
    }

    /// A failure part way through: the messages already served still arrive, and the
    /// error names the batch that failed rather than the one that worked.
    #[tokio::test]
    async fn messages_served_before_a_failure_are_still_delivered() {
        let indexer = ZoneIndexer::new(channel_id(), ScriptedNode::serving_one_batch());
        let stream = indexer
            .next_messages(None)
            .await
            .expect("consensus_info is reachable");

        let items: Vec<_> = stream.collect().await;

        assert_eq!(items.len(), 2, "one message then one error: {items:?}");
        assert_eq!(
            items[0].as_ref().expect("the first batch served").1,
            Slot::genesis()
        );
        let Err(Error::Fetch { from, to, .. }) = &items[1] else {
            panic!("expected the second batch to fail: {items:?}");
        };
        assert_eq!((*from, *to), (Slot::from(100), Slot::from(199)));
    }
}
