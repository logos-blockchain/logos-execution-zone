//! Bounds every [`Node`] call: the SDK's HTTP client has no timeout, so a
//! lost response would hang a poller forever.

use std::{future::Future, time::Duration};

use async_trait::async_trait;
use futures::StreamExt as _;
use log::warn;
use logos_blockchain_core::mantle::ledger::verification_mode::StandardMode;
use logos_blockchain_zone_sdk::{
    adapter::{BoxStream, Node},
    node_types::{
        ApiBlock, BlockInfo, ChainServiceInfo, ChannelId, ChannelState, Error, Events, HeaderId,
        ProcessedBlockEvent, SignedOps, Slot, TimeInfo, Unverified, WalletFundRequestBody,
        WalletFundResponseBody,
    },
};

pub const NODE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Deliberately generous: it only has to tell a dead subscription from a quiet
/// chain, and tripping a healthy one costs a stand-down until it reconnects.
pub const NODE_STREAM_IDLE_TIMEOUT: Duration = Duration::from_mins(10);

/// Inherits the default `zone_messages_*`, dropping any backend override.
#[derive(Clone)]
pub struct TimeoutNode<N> {
    inner: N,
}

impl<N> TimeoutNode<N> {
    pub const fn new(inner: N) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<N: Node + Sync> Node for TimeoutNode<N> {
    async fn consensus_info(&self) -> Result<ChainServiceInfo, Error> {
        bounded(self.inner.consensus_info()).await
    }

    async fn time_info(&self) -> Result<TimeInfo, Error> {
        bounded(self.inner.time_info()).await
    }

    async fn channel_state(&self, channel_id: ChannelId) -> Result<Option<ChannelState>, Error> {
        bounded(self.inner.channel_state(channel_id)).await
    }

    async fn block_stream(&self) -> Result<BoxStream<ProcessedBlockEvent>, Error> {
        bounded(self.inner.block_stream())
            .await
            .map(|stream| idle_bounded(stream, "block stream"))
    }

    async fn lib_stream(&self) -> Result<BoxStream<BlockInfo>, Error> {
        bounded(self.inner.lib_stream())
            .await
            .map(|stream| idle_bounded(stream, "LIB stream"))
    }

    async fn block(&self, id: HeaderId) -> Result<Option<ApiBlock>, Error> {
        bounded(self.inner.block(id)).await
    }

    async fn block_events(&self, id: HeaderId) -> Result<Option<Events>, Error> {
        bounded(self.inner.block_events(id)).await
    }

    async fn immutable_blocks(
        &self,
        slot_from: Slot,
        slot_to: Slot,
    ) -> Result<Vec<ApiBlock>, Error> {
        bounded(self.inner.immutable_blocks(slot_from, slot_to)).await
    }

    async fn post_transaction(&self, tx: SignedOps<Unverified, StandardMode>) -> Result<(), Error> {
        bounded(self.inner.post_transaction(tx)).await
    }

    async fn fund_tx(
        &self,
        request: WalletFundRequestBody,
    ) -> Result<WalletFundResponseBody, Error> {
        bounded(self.inner.fund_tx(request)).await
    }
}

async fn bounded<T>(call: impl Future<Output = Result<T, Error>> + Send) -> Result<T, Error> {
    tokio::time::timeout(NODE_REQUEST_TIMEOUT, call)
        .await
        .unwrap_or_else(|_| {
            Err(Error::Client(format!(
                "node request timed out after {NODE_REQUEST_TIMEOUT:?}"
            )))
        })
}

/// Ends a subscription that stops delivering, which the SDK's block-stream
/// reader treats as a disconnect and reopens. Silence otherwise looks healthy.
fn idle_bounded<T: Send + 'static>(stream: BoxStream<T>, kind: &'static str) -> BoxStream<T> {
    Box::pin(
        futures::stream::unfold(Some(stream), move |state| async move {
            let mut live = state?;
            let Ok(item) = tokio::time::timeout(NODE_STREAM_IDLE_TIMEOUT, live.next()).await else {
                warn!(
                    "Node {kind} delivered nothing for {NODE_STREAM_IDLE_TIMEOUT:?}; ending it so its reader reconnects"
                );
                return None;
            };
            Some((item?, Some(live)))
        })
        .fuse(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NeverNode;

    #[async_trait]
    impl Node for NeverNode {
        async fn consensus_info(&self) -> Result<ChainServiceInfo, Error> {
            std::future::pending().await
        }

        async fn time_info(&self) -> Result<TimeInfo, Error> {
            std::future::pending().await
        }

        async fn channel_state(&self, _: ChannelId) -> Result<Option<ChannelState>, Error> {
            std::future::pending().await
        }

        async fn block_stream(&self) -> Result<BoxStream<ProcessedBlockEvent>, Error> {
            std::future::pending().await
        }

        async fn lib_stream(&self) -> Result<BoxStream<BlockInfo>, Error> {
            std::future::pending().await
        }

        async fn block(&self, _: HeaderId) -> Result<Option<ApiBlock>, Error> {
            std::future::pending().await
        }

        async fn block_events(&self, _: HeaderId) -> Result<Option<Events>, Error> {
            std::future::pending().await
        }

        async fn immutable_blocks(&self, _: Slot, _: Slot) -> Result<Vec<ApiBlock>, Error> {
            std::future::pending().await
        }

        async fn post_transaction(
            &self,
            _: SignedOps<Unverified, StandardMode>,
        ) -> Result<(), Error> {
            std::future::pending().await
        }

        async fn fund_tx(&self, _: WalletFundRequestBody) -> Result<WalletFundResponseBody, Error> {
            std::future::pending().await
        }
    }

    fn channel() -> (futures::channel::mpsc::UnboundedSender<u8>, BoxStream<u8>) {
        let (tx, rx) = futures::channel::mpsc::unbounded();
        (tx, Box::pin(rx))
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_that_stops_delivering_ends() {
        let (tx, rx) = channel();
        tx.unbounded_send(7).expect("the receiver is live");
        let mut bounded = idle_bounded(rx, "test");
        assert_eq!(bounded.next().await, Some(7));
        assert_eq!(bounded.next().await, None);
    }

    /// The property the design rests on: readers poll this inside a `select!`,
    /// which drops the losing branch's future on every lost race.
    #[tokio::test(start_paused = true)]
    async fn a_cancelled_poll_keeps_the_item() {
        let (tx, rx) = channel();
        let mut bounded = idle_bounded(rx, "test");
        // What a lost `select!` race does: poll, then drop the `next` future.
        for _ in 0..5 {
            assert!(
                futures::poll!(bounded.next()).is_pending(),
                "nothing was sent yet"
            );
        }
        tx.unbounded_send(7).expect("the receiver is live");
        assert_eq!(bounded.next().await, Some(7));
    }

    #[tokio::test(start_paused = true)]
    async fn items_inside_the_window_keep_the_stream_alive() {
        let (tx, rx) = channel();
        tokio::spawn(async move {
            for item in 0..3 {
                tokio::time::sleep(NODE_STREAM_IDLE_TIMEOUT.mul_f32(0.9)).await;
                if tx.unbounded_send(item).is_err() {
                    return;
                }
            }
        });
        let mut bounded = idle_bounded(rx, "test");
        for expected in 0..3 {
            assert_eq!(bounded.next().await, Some(expected));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_unpolled_stream_keeps_its_full_window() {
        let (tx, rx) = channel();
        let mut bounded = idle_bounded(rx, "test");
        tokio::time::sleep(NODE_STREAM_IDLE_TIMEOUT * 2).await;
        tx.unbounded_send(7).expect("the receiver is live");
        assert_eq!(bounded.next().await, Some(7));
    }

    #[tokio::test(start_paused = true)]
    async fn an_ended_stream_can_be_polled_again() {
        let mut bounded = idle_bounded(Box::pin(futures::stream::empty::<u8>()), "test");
        assert_eq!(bounded.next().await, None);
        assert_eq!(bounded.next().await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_call_that_never_answers_returns_an_error() {
        let err = TimeoutNode::new(NeverNode)
            .consensus_info()
            .await
            .expect_err("a hung call must time out");
        assert!(err.to_string().contains("timed out"));
    }
}
