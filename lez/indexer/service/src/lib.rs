use std::{net::SocketAddr, path::Path};

use anyhow::{Context as _, Result};
pub use indexer_core::config::*;
use indexer_service_rpc::RpcServer as _;
use jsonrpsee::server::{Server, ServerHandle};
use log::{error, info};
use tokio_util::sync::CancellationToken;

pub mod service;

#[cfg(feature = "mock-responses")]
pub mod mock_service;

pub struct IndexerHandle {
    addr: SocketAddr,
    /// Option because of `Drop` which forbids to simply move out of `self` in `stopped()`.
    server_handle: Option<ServerHandle>,
    subscription_shutdown: Option<service::SubscriptionShutdown>,
}

impl IndexerHandle {
    const fn new(
        addr: SocketAddr,
        server_handle: ServerHandle,
        subscription_shutdown: Option<service::SubscriptionShutdown>,
    ) -> Self {
        Self {
            addr,
            server_handle: Some(server_handle),
            subscription_shutdown,
        }
    }

    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Wait for all Indexer tasks to stop.
    pub async fn stopped(mut self) {
        let handle = self
            .server_handle
            .take()
            .expect("Indexer server handle is set");

        handle.stopped().await;
    }

    /// Stops the ingestion task and RPC server, waiting for both to terminate.
    pub async fn shutdown(mut self) -> Result<()> {
        let handle = self
            .server_handle
            .take()
            .expect("Indexer server handle is set");

        let subscription_result =
            if let Some(subscription_shutdown) = self.subscription_shutdown.take() {
                subscription_shutdown.shutdown().await
            } else {
                Ok(())
            };
        let stop_result = handle.stop().context("failed to stop Indexer RPC server");
        handle.stopped().await;
        subscription_result?;
        stop_result
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.server_handle
            .as_ref()
            .is_some_and(|handle| !handle.is_stopped())
    }
}

impl Drop for IndexerHandle {
    fn drop(&mut self) {
        let Self {
            addr: _,
            server_handle,
            subscription_shutdown: _,
        } = self;

        let Some(handle) = server_handle else {
            return;
        };

        if let Err(err) = handle.stop() {
            error!("An error occurred while stopping Indexer RPC server: {err}");
        }
    }
}

pub async fn run_server(
    config: IndexerConfig,
    storage_dir: &Path,
    port: u16,
    shutdown: CancellationToken,
) -> Result<IndexerHandle> {
    #[cfg(feature = "mock-responses")]
    let _ = (config, storage_dir, shutdown);

    let server = Server::builder()
        .build(SocketAddr::from(([0, 0, 0, 0], port)))
        .await
        .context("Failed to build RPC server")?;

    let addr = server
        .local_addr()
        .context("Failed to get local address of RPC server")?;

    info!("Starting Indexer Service RPC server on {addr}");

    #[cfg(not(feature = "mock-responses"))]
    let (handle, subscription_shutdown) = {
        let service = service::IndexerService::new(config, storage_dir, shutdown.child_token())
            .await
            .context("Failed to initialize indexer service")?;
        let subscription_shutdown = Some(service.subscription_shutdown());
        (server.start(service.into_rpc()), subscription_shutdown)
    };
    #[cfg(feature = "mock-responses")]
    let (handle, subscription_shutdown) = (
        server.start(mock_service::MockIndexerService::new_with_mock_blocks().into_rpc()),
        None,
    );

    Ok(IndexerHandle::new(addr, handle, subscription_shutdown))
}
