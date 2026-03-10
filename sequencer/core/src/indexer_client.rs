use std::{ops::Deref, sync::Arc};

use anyhow::{Context as _, Result};
use log::info;
pub use url::Url;

#[expect(async_fn_in_trait, reason = "We don't care about Send/Sync here")]
pub trait IndexerClientTrait: Clone {
    async fn new(indexer_url: &Url) -> Result<Self>;
}

#[derive(Clone)]
pub struct IndexerClient(Arc<jsonrpsee::ws_client::WsClient>);

impl IndexerClientTrait for IndexerClient {
    async fn new(indexer_url: &Url) -> Result<Self> {
        info!("Connecting to Indexer at {indexer_url}");

        let client = jsonrpsee::ws_client::WsClientBuilder::default()
            .build(indexer_url)
            .await
            .context("Failed to create websocket client")?;

        Ok(Self(Arc::new(client)))
    }
}

impl Deref for IndexerClient {
    type Target = jsonrpsee::ws_client::WsClient;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
