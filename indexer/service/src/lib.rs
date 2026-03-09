use std::net::SocketAddr;

use anyhow::{Context as _, Result};
pub use indexer_core::config::*;
use indexer_service_rpc::RpcServer as _;
use jsonrpsee::server::Server;
use log::{error, info};

pub mod service;

#[cfg(feature = "mock-responses")]
pub mod mock_service;

pub struct IndexerHandle {
    addr: SocketAddr,
    server_handle: Option<jsonrpsee::server::ServerHandle>,
}
impl IndexerHandle {
    const fn new(addr: SocketAddr, server_handle: jsonrpsee::server::ServerHandle) -> Self {
        Self {
            addr,
            server_handle: Some(server_handle),
        }
    }

    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn stopped(mut self) {
        let handle = self
            .server_handle
            .take()
            .expect("Indexer server handle is set");

        handle.stopped().await;
    }

    #[expect(
        clippy::redundant_closure_for_method_calls,
        reason = "Clippy suggested path jsonrpsee::jsonrpsee_server::ServerHandle is not accessible"
    )]
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.server_handle
            .as_ref()
            .is_none_or(|handle| handle.is_stopped())
    }
}

impl Drop for IndexerHandle {
    fn drop(&mut self) {
        let Self {
            addr: _,
            server_handle,
        } = self;

        let Some(handle) = server_handle else {
            return;
        };

        if let Err(err) = handle.stop() {
            error!("An error occurred while stopping Indexer RPC server: {err}");
        }
    }
}

pub async fn run_server(config: IndexerConfig, port: u16) -> Result<IndexerHandle> {
    #[cfg(feature = "mock-responses")]
    let _ = config;

    let server = Server::builder()
        .build(SocketAddr::from(([0, 0, 0, 0], port)))
        .await
        .context("Failed to build RPC server")?;

    let addr = server
        .local_addr()
        .context("Failed to get local address of RPC server")?;

    info!("Starting Indexer Service RPC server on {addr}");

    #[cfg(not(feature = "mock-responses"))]
    let handle = {
        let service =
            service::IndexerService::new(config).context("Failed to initialize indexer service")?;
        server.start(service.into_rpc())
    };
    #[cfg(feature = "mock-responses")]
    let handle = server.start(mock_service::MockIndexerService::new_with_mock_blocks().into_rpc());

    Ok(IndexerHandle::new(addr, handle))
}
