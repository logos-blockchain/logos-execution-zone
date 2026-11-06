//! Bounds every [`Node`] call: the SDK's HTTP client has no timeout, so a
//! lost response would hang a poller forever.

use std::{future::Future, time::Duration};

use async_trait::async_trait;
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
        bounded(self.inner.block_stream()).await
    }

    async fn lib_stream(&self) -> Result<BoxStream<BlockInfo>, Error> {
        bounded(self.inner.lib_stream()).await
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

    #[tokio::test(start_paused = true)]
    async fn a_call_that_never_answers_returns_an_error() {
        let err = TimeoutNode::new(NeverNode)
            .consensus_info()
            .await
            .expect_err("a hung call must time out");
        assert!(err.to_string().contains("timed out"));
    }
}
