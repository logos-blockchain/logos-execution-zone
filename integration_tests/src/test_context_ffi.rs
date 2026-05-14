use std::sync::Arc;

use anyhow::{Context as _, Result};
use futures::FutureExt as _;
use indexer_ffi::IndexerServiceFFI;
use indexer_service_rpc::RpcClient as _;
use log::{debug, error};
use nssa::AccountId;
use sequencer_core::indexer_client::{IndexerClient, IndexerClientTrait as _};
use sequencer_service::SequencerHandle;
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};
use tempfile::TempDir;
use testcontainers::compose::DockerCompose;
use wallet::WalletCore;

use crate::{
    BEDROCK_SERVICE_WITH_OPEN_PORT, LOGGER, TestContextBuilder, config,
    setup::{setup_bedrock_node, setup_indexer_ffi, setup_sequencer, setup_wallet},
};

/// Test context which sets up a sequencer, indexer through ffi and a wallet for integration tests.
///
/// It's memory and logically safe to create multiple instances of this struct in parallel tests,
/// as each instance uses its own temporary directories for sequencer and wallet data.
// NOTE: Order of fields is important for proper drop order.
pub struct TestContextFFI {
    sequencer_client: SequencerClient,
    indexer_client: IndexerClient,
    wallet: WalletCore,
    wallet_password: String,
    /// Optional to move out value in Drop.
    sequencer_handle: Option<SequencerHandle>,
    bedrock_compose: DockerCompose,
    _temp_indexer_dir: TempDir,
    _temp_sequencer_dir: TempDir,
    _temp_wallet_dir: TempDir,
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "It is more natural to have this implementation here"
)]
impl TestContextBuilder {
    pub fn build_ffi(
        self,
        runtime: &Arc<tokio::runtime::Runtime>,
    ) -> Result<(TestContextFFI, IndexerServiceFFI)> {
        TestContextFFI::new_configured(
            self.sequencer_partial_config.unwrap_or_default(),
            &self.initial_data.unwrap_or_else(|| {
                config::InitialData::with_two_public_and_two_private_initialized_accounts()
            }),
            runtime,
        )
    }
}

impl TestContextFFI {
    /// Create new test context.
    pub fn new(runtime: &Arc<tokio::runtime::Runtime>) -> Result<(Self, IndexerServiceFFI)> {
        Self::builder().build_ffi(runtime)
    }

    #[must_use]
    pub const fn builder() -> TestContextBuilder {
        TestContextBuilder::new()
    }

    fn new_configured(
        sequencer_partial_config: config::SequencerPartialConfig,
        initial_data: &config::InitialData,
        runtime: &Arc<tokio::runtime::Runtime>,
    ) -> Result<(Self, IndexerServiceFFI)> {
        // Ensure logger is initialized only once
        *LOGGER;

        debug!("Test context setup");

        let (bedrock_compose, bedrock_addr) = runtime.block_on(setup_bedrock_node())?;

        let (indexer_ffi, temp_indexer_dir) =
            setup_indexer_ffi(bedrock_addr, initial_data).context("Failed to setup Indexer")?;

        let (sequencer_handle, temp_sequencer_dir) = runtime
            .block_on(setup_sequencer(
                sequencer_partial_config,
                bedrock_addr,
                // SAFETY: addr is valid if indexer_ffi is valid.
                unsafe { indexer_ffi.addr() },
                initial_data,
            ))
            .context("Failed to setup Sequencer")?;

        let (wallet, temp_wallet_dir, wallet_password) = runtime
            .block_on(setup_wallet(sequencer_handle.addr(), initial_data))
            .context("Failed to setup wallet")?;

        let sequencer_url = config::addr_to_url(config::UrlProtocol::Http, sequencer_handle.addr())
            .context("Failed to convert sequencer addr to URL")?;
        let indexer_url = config::addr_to_url(
            config::UrlProtocol::Ws,
            // SAFETY: addr is valid if indexer_ffi is valid.
            unsafe { indexer_ffi.addr() },
        )
        .context("Failed to convert indexer addr to URL")?;
        let sequencer_client = SequencerClientBuilder::default()
            .build(sequencer_url)
            .context("Failed to create sequencer client")?;
        let indexer_client = runtime
            .block_on(IndexerClient::new(&indexer_url))
            .context("Failed to create indexer client")?;

        Ok((
            Self {
                sequencer_client,
                indexer_client,
                wallet,
                wallet_password,
                bedrock_compose,
                sequencer_handle: Some(sequencer_handle),
                _temp_indexer_dir: temp_indexer_dir,
                _temp_sequencer_dir: temp_sequencer_dir,
                _temp_wallet_dir: temp_wallet_dir,
            },
            indexer_ffi,
        ))
    }

    /// Get reference to the wallet.
    #[must_use]
    pub const fn wallet(&self) -> &WalletCore {
        &self.wallet
    }

    #[must_use]
    pub fn wallet_password(&self) -> &str {
        &self.wallet_password
    }

    /// Get mutable reference to the wallet.
    pub const fn wallet_mut(&mut self) -> &mut WalletCore {
        &mut self.wallet
    }

    /// Get reference to the sequencer client.
    #[must_use]
    pub const fn sequencer_client(&self) -> &SequencerClient {
        &self.sequencer_client
    }

    /// Get reference to the indexer client.
    #[must_use]
    pub const fn indexer_client(&self) -> &IndexerClient {
        &self.indexer_client
    }

    /// Get existing public account IDs in the wallet.
    #[must_use]
    pub fn existing_public_accounts(&self) -> Vec<AccountId> {
        self.wallet
            .storage()
            .user_data
            .public_account_ids()
            .collect()
    }

    /// Get existing private account IDs in the wallet.
    #[must_use]
    pub fn existing_private_accounts(&self) -> Vec<AccountId> {
        self.wallet
            .storage()
            .user_data
            .private_account_ids()
            .collect()
    }

    pub fn get_last_block_sequencer(&self, runtime: &Arc<tokio::runtime::Runtime>) -> Result<u64> {
        Ok(runtime.block_on(self.sequencer_client.get_last_block_id())?)
    }

    pub fn get_last_block_indexer(&self, runtime: &Arc<tokio::runtime::Runtime>) -> Result<u64> {
        Ok(runtime.block_on(self.indexer_client.get_last_finalized_block_id())?)
    }
}

impl Drop for TestContextFFI {
    fn drop(&mut self) {
        let Self {
            sequencer_handle,
            bedrock_compose,
            _temp_indexer_dir: _,
            _temp_sequencer_dir: _,
            _temp_wallet_dir: _,
            sequencer_client: _,
            indexer_client: _,
            wallet: _,
            wallet_password: _,
        } = self;

        let sequencer_handle = sequencer_handle
            .take()
            .expect("Sequencer handle should be present in TestContext drop");
        if !sequencer_handle.is_healthy() {
            let Err(err) = sequencer_handle
                .failed()
                .now_or_never()
                .expect("Sequencer handle should not be running");
            error!(
                "Sequencer handle has unexpectedly stopped before TestContext drop with error: {err:#}"
            );
        }

        let container = bedrock_compose
            .service(BEDROCK_SERVICE_WITH_OPEN_PORT)
            .unwrap_or_else(|| {
                panic!("Failed to get Bedrock service container `{BEDROCK_SERVICE_WITH_OPEN_PORT}`")
            });
        let output = std::process::Command::new("docker")
            .args(["inspect", "-f",  "{{.State.Running}}", container.id()])
            .output()
            .expect("Failed to execute docker inspect command to check if Bedrock container is still running");
        let stdout = String::from_utf8(output.stdout)
            .expect("Failed to parse docker inspect output as String");
        if stdout.trim() != "true" {
            error!(
                "Bedrock container `{}` is not running during TestContext drop, docker inspect output: {stdout}",
                container.id()
            );
        }
    }
}

/// A test context with ffi to be used in normal #[test] tests.
pub struct BlockingTestContextFFI {
    ctx: Option<TestContextFFI>,
    runtime: Arc<tokio::runtime::Runtime>,
    indexer_ffi: IndexerServiceFFI,
}

impl BlockingTestContextFFI {
    pub fn new() -> Result<Self> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let runtime_wrapped = Arc::new(runtime);
        let (ctx, indexer_ffi) = TestContextFFI::new(&runtime_wrapped)?;
        Ok(Self {
            ctx: Some(ctx),
            runtime: runtime_wrapped,
            indexer_ffi,
        })
    }

    #[must_use]
    pub const fn ctx(&self) -> &TestContextFFI {
        self.ctx.as_ref().expect("TestContext is set")
    }

    #[must_use]
    pub const fn ctx_mut(&mut self) -> &mut TestContextFFI {
        self.ctx.as_mut().expect("TestContext is set")
    }

    #[must_use]
    pub const fn runtime(&self) -> &Arc<tokio::runtime::Runtime> {
        &self.runtime
    }

    #[must_use]
    pub fn runtime_clone(&self) -> Arc<tokio::runtime::Runtime> {
        Arc::<tokio::runtime::Runtime>::clone(&self.runtime)
    }
}

impl Drop for BlockingTestContextFFI {
    fn drop(&mut self) {
        let Self {
            ctx,
            runtime,
            indexer_ffi,
        } = self;

        // Ensure async cleanup of TestContext by blocking on its drop in the runtime.
        runtime.block_on(async {
            if let Some(ctx) = ctx.take() {
                drop(ctx);
            }
        });

        let indexer_handle =
        // SAFETY: lib function ensures validity of value.
        unsafe { indexer_ffi.handle() };

        if !indexer_handle.is_healthy() {
            error!("Indexer handle has unexpectedly stopped before TestContext drop");
        }
    }
}
