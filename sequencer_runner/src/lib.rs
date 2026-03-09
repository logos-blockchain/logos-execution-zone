use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use actix_web::dev::ServerHandle;
use anyhow::{Context as _, Result};
use clap::Parser;
use common::rpc_primitives::RpcConfig;
use futures::{FutureExt as _, never::Never};
#[cfg(not(feature = "standalone"))]
use log::warn;
use log::{error, info};
#[cfg(feature = "standalone")]
use sequencer_core::SequencerCoreWithMockClients as SequencerCore;
use sequencer_core::config::SequencerConfig;
#[cfg(not(feature = "standalone"))]
use sequencer_core::SequencerCore;
use sequencer_rpc::new_http_server;
use tokio::{sync::Mutex, task::JoinHandle};

pub const RUST_LOG: &str = "RUST_LOG";

#[derive(Parser, Debug)]
#[clap(version)]
struct Args {
    /// Path to configs
    home_dir: PathBuf,
}

/// Handle to manage the sequencer and its tasks.
///
/// Implements `Drop` to ensure all tasks are aborted and the HTTP server is stopped when dropped.
pub struct SequencerHandle {
    addr: SocketAddr,
    http_server_handle: ServerHandle,
    main_loop_handle: JoinHandle<Result<Never>>,
    listen_for_bedrock_blocks_loop_handle: JoinHandle<Result<Never>>,
}

impl SequencerHandle {
    /// Runs the sequencer indefinitely, monitoring its tasks.
    ///
    /// If no error occurs, this function will never return.
    pub async fn run_forever(&mut self) -> Result<Never> {
        let Self {
            addr: _,
            http_server_handle: _,
            main_loop_handle,
            listen_for_bedrock_blocks_loop_handle,
        } = self;

        tokio::select! {
            res = main_loop_handle => {
                res
                   .context("Main loop task panicked")?
                   .context("Main loop exited unexpectedly")
            }
            res = listen_for_bedrock_blocks_loop_handle => {
                res
                   .context("Listen for bedrock blocks loop task panicked")?
                   .context("Listen for bedrock blocks loop exited unexpectedly")
            }
        }
    }

    pub fn is_finished(&self) -> bool {
        self.main_loop_handle.is_finished()
            || self.listen_for_bedrock_blocks_loop_handle.is_finished()
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for SequencerHandle {
    fn drop(&mut self) {
        let Self {
            addr: _,
            http_server_handle,
            main_loop_handle,
            listen_for_bedrock_blocks_loop_handle,
        } = self;

        main_loop_handle.abort();
        listen_for_bedrock_blocks_loop_handle.abort();

        // Can't wait here as Drop can't be async, but anyway stop signal should be sent
        http_server_handle.stop(true).now_or_never();
    }
}

pub async fn startup_sequencer(app_config: SequencerConfig) -> Result<SequencerHandle> {
    let block_timeout = app_config.block_create_timeout;
    let port = app_config.port;

    let (sequencer_core, mempool_handle) = SequencerCore::start_from_config(app_config).await;

    info!("Sequencer core set up");

    let seq_core_wrapped = Arc::new(Mutex::new(sequencer_core));

    let (http_server, addr) = new_http_server(
        RpcConfig::with_port(port),
        Arc::clone(&seq_core_wrapped),
        mempool_handle,
    )
    .await?;
    info!("HTTP server started");
    let http_server_handle = http_server.handle();
    tokio::spawn(http_server);

    info!("Starting main sequencer loop");
    let main_loop_handle = tokio::spawn(main_loop(Arc::clone(&seq_core_wrapped), block_timeout));

    info!("Starting bedrock block listening loop");
    let listen_for_bedrock_blocks_loop_handle =
        tokio::spawn(listen_for_bedrock_blocks_loop(seq_core_wrapped));

    Ok(SequencerHandle {
        addr,
        http_server_handle,
        main_loop_handle,
        listen_for_bedrock_blocks_loop_handle,
    })
}

async fn main_loop(seq_core: Arc<Mutex<SequencerCore>>, block_timeout: Duration) -> Result<Never> {
    loop {
        tokio::time::sleep(block_timeout).await;

        info!("Collecting transactions from mempool, block creation");

        let id = {
            let mut state = seq_core.lock().await;

            state.produce_new_block().await?
        };

        info!("Block with id {id} created");

        info!("Waiting for new transactions");
    }
}

#[cfg(not(feature = "standalone"))]
async fn listen_for_bedrock_blocks_loop(seq_core: Arc<Mutex<SequencerCore>>) -> Result<Never> {
    use indexer_service_rpc::RpcClient as _;

    let indexer_client = seq_core.lock().await.indexer_client();

    let retry_delay = Duration::from_secs(5);

    loop {
        // TODO: Subscribe from the first pending block ID?
        let mut subscription = indexer_client
            .subscribe_to_finalized_blocks()
            .await
            .context("Failed to subscribe to finalized blocks")?;

        while let Some(block_id) = subscription.next().await {
            let block_id = block_id.context("Failed to get next block from subscription")?;

            info!("Received new L2 block with ID {block_id}");

            seq_core
                .lock()
                .await
                .clean_finalized_blocks_from_db(block_id)
                .with_context(|| {
                    format!("Failed to clean finalized blocks from DB for block ID {block_id}")
                })?;
        }

        warn!(
            "Block subscription closed unexpectedly, reason: {:?}, retrying after {retry_delay:?}",
            subscription.close_reason()
        );
        tokio::time::sleep(retry_delay).await;
    }
}

#[cfg(feature = "standalone")]
async fn listen_for_bedrock_blocks_loop(_seq_core: Arc<Mutex<SequencerCore>>) -> Result<Never> {
    std::future::pending::<Result<Never>>().await
}

pub async fn main_runner() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    let Args { home_dir } = args;

    let app_config = SequencerConfig::from_path(&home_dir.join("sequencer_config.json"))?;

    if let Some(ref rust_log) = app_config.override_rust_log {
        info!("RUST_LOG env var set to {rust_log:?}");

        unsafe {
            std::env::set_var(RUST_LOG, rust_log);
        }
    }

    // ToDo: Add restart on failures
    let mut sequencer_handle = startup_sequencer(app_config).await?;

    info!("Sequencer running. Monitoring concurrent tasks...");

    let Err(err) = sequencer_handle.run_forever().await;
    error!("Sequencer failed: {err:#}");

    info!("Shutting down sequencer...");

    Ok(())
}
