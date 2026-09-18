use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Context as _;
use async_trait::async_trait;
use indexer_service::IndexerHandle;
use tempfile::TempDir;
use testing_framework_app::{AppDeployment, AppHostEnv, DeployContext};
use testing_framework_core::scenario::DynError;

use crate::{
    config::{self, UrlProtocol},
    indexer_client::IndexerClient,
    setup::setup_indexer,
};

struct IndexerInstance {
    client: Arc<IndexerClient>,
    service: Mutex<Option<IndexerHandle>>,
    _state_dir: Option<TempDir>,
}

/// Client and lifetime handle for a deployed LEZ indexer.
///
/// Clones share the existing indexer client and keep the indexer service and
/// its state directory alive until the final clone is dropped.
#[derive(Clone)]
pub struct LezIndexerClient(Arc<IndexerInstance>);

impl LezIndexerClient {
    fn new(client: Arc<IndexerClient>, service: IndexerHandle, state_dir: Option<TempDir>) -> Self {
        Self(Arc::new(IndexerInstance {
            client,
            service: Mutex::new(Some(service)),
            _state_dir: state_dir,
        }))
    }

    /// Returns the existing LEZ indexer client.
    #[must_use]
    pub fn client(&self) -> &IndexerClient {
        &self.0.client
    }

    /// Stops the indexer service and waits for its RPC server to terminate.
    /// Repeated calls are harmless.
    pub async fn shutdown(&self) -> Result<(), DynError> {
        let service = self
            .0
            .service
            .lock()
            .map_err(|error| anyhow::anyhow!("LEZ indexer shutdown lock poisoned: {error}"))?
            .take();

        if let Some(service) = service {
            service.shutdown().await?;
        }

        Ok(())
    }
}

/// Deployable LEZ indexer configured with an explicit Bedrock API address.
#[derive(Clone)]
pub struct IndexerApp {
    bedrock_addr: SocketAddr,
    state_dir: Option<PathBuf>,
}

impl IndexerApp {
    /// Creates an indexer deployment connected to `bedrock_addr`.
    #[must_use]
    pub const fn new(bedrock_addr: SocketAddr) -> Self {
        Self {
            bedrock_addr,
            state_dir: None,
        }
    }

    /// Places indexer state and logs below the supplied scenario artifact
    /// directory.
    #[must_use]
    pub fn with_state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(dir.into());
        self
    }
}

#[async_trait]
impl AppDeployment<AppHostEnv> for IndexerApp {
    type Handle = LezIndexerClient;

    async fn deploy(self, _ctx: &mut DeployContext<AppHostEnv>) -> Result<Self::Handle, DynError> {
        // If the indexer moves to a separate process, create a `LocalProcessApp`
        // with its `LaunchSpec` here so TF owns the process lifecycle.
        let (service, state_dir);
        if let Some(home) = self.state_dir {
            service = crate::setup::setup_indexer_at(
                self.bedrock_addr,
                config::bedrock_channel_id(),
                None,
                &home,
            )
            .await
            .context("failed to set up LEZ indexer")?;
            state_dir = None;
        } else {
            let (indexer, temp_dir) =
                setup_indexer(self.bedrock_addr, config::bedrock_channel_id(), None)
                    .await
                    .context("failed to set up LEZ indexer")?;
            service = indexer;
            state_dir = Some(temp_dir);
        }
        let url = config::addr_to_url(UrlProtocol::Ws, service.addr())?;
        let client = Arc::new(IndexerClient::new(&url).await?);

        Ok(LezIndexerClient::new(client, service, state_dir))
    }
}
