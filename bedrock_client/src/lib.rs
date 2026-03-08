use std::time::Duration;

use anyhow::{Context as _, Result};
use common::config::BasicAuth;
use futures::{Stream, TryFutureExt};
#[expect(clippy::single_component_path_imports, reason = "Satisfy machete")]
use humantime_serde;
use log::{info, warn};
pub use logos_blockchain_chain_broadcast_service::BlockInfo;
use logos_blockchain_chain_service::CryptarchiaInfo;
pub use logos_blockchain_common_http_client::{CommonHttpClient, Error};
pub use logos_blockchain_core::{block::Block, header::HeaderId, mantle::SignedMantleTx};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use tokio_retry::Retry;

/// Fibonacci backoff retry strategy configuration
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct BackoffConfig {
    #[serde(with = "humantime_serde")]
    pub start_delay: Duration,
    pub max_retries: usize,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            start_delay: Duration::from_millis(100),
            max_retries: 5,
        }
    }
}

/// Simple wrapper
/// maybe extend in the future for our purposes
/// `Clone` is cheap because `CommonHttpClient` is internally reference counted (`Arc`).
#[derive(Clone)]
pub struct BedrockClient {
    http_client: CommonHttpClient,
    node_url: Url,
    backoff: BackoffConfig,
}

impl BedrockClient {
    pub fn new(backoff: BackoffConfig, node_url: Url, auth: Option<BasicAuth>) -> Result<Self> {
        info!("Creating Bedrock client with node URL {node_url}");
        let client = Client::builder()
                //Add more fields if needed
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .context("Failed to build HTTP client")?;

        let auth = auth.map(|a| {
            logos_blockchain_common_http_client::BasicAuthCredentials::new(a.username, a.password)
        });

        let http_client = CommonHttpClient::new_with_client(client, auth);
        Ok(Self {
            http_client,
            node_url,
            backoff,
        })
    }

    pub async fn post_transaction(&self, tx: SignedMantleTx) -> Result<Result<(), Error>, Error> {
        Retry::spawn(self.backoff_strategy(), || async {
            match self
                .http_client
                .post_transaction(self.node_url.clone(), tx.clone())
                .await
            {
                Ok(_) => Ok(Ok(())),
                Err(err) => match err {
                    // Retry arm.
                    // Retrying only reqwest errors: mainly connected to http.
                    Error::Request(_) => Err(err),
                    // Returning non-retryable error
                    _ => Ok(Err(err)),
                },
            }
        })
        .await
    }

    pub async fn get_lib_stream(&self) -> Result<impl Stream<Item = BlockInfo>, Error> {
        self.http_client.get_lib_stream(self.node_url.clone()).await
    }

    pub async fn get_block_by_id(
        &self,
        header_id: HeaderId,
    ) -> Result<Option<Block<SignedMantleTx>>, Error> {
        Retry::spawn(self.backoff_strategy(), || {
            self.http_client
                .get_block_by_id(self.node_url.clone(), header_id)
                .inspect_err(|err| warn!("Block fetching failed with error: {err:#}"))
        })
        .await
    }

    pub async fn get_consensus_info(&self) -> Result<CryptarchiaInfo, Error> {
        Retry::spawn(self.backoff_strategy(), || {
            self.http_client
                .consensus_info(self.node_url.clone())
                .inspect_err(|err| warn!("Block fetching failed with error: {err:#}"))
        })
        .await
    }

    fn backoff_strategy(&self) -> impl Iterator<Item = Duration> {
        tokio_retry::strategy::FibonacciBackoff::from_millis(
            self.backoff.start_delay.as_millis() as u64
        )
        .take(self.backoff.max_retries)
    }
}
