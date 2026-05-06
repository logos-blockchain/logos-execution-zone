//! Thin client wrapper for querying the indexer's JSON-RPC API in tests.
//!
//! The sequencer doesn't depend on the indexer at runtime — finalization comes
//! from zone-sdk events. This wrapper exists purely for test ergonomics so
//! integration tests can construct a single connection and call
//! `indexer_service_rpc::RpcClient` methods directly via `Deref`.

use std::ops::Deref;

use anyhow::{Context as _, Result};
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use log::info;
use url::Url;

pub struct IndexerClient(WsClient);

impl IndexerClient {
    pub async fn new(indexer_url: &Url) -> Result<Self> {
        info!("Connecting to Indexer at {indexer_url}");
        let client = WsClientBuilder::default()
            .build(indexer_url)
            .await
            .context("Failed to create websocket client")?;
        Ok(Self(client))
    }
}

impl Deref for IndexerClient {
    type Target = WsClient;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
