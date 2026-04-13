use std::{
    ffi::{CString, c_char},
    fs::File,
    io::Write as _,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context as _, Result, bail};
use futures::FutureExt as _;
use indexer_ffi::{IndexerServiceFFI, api::lifecycle::InitializedIndexerServiceFFIResult};
use indexer_service_rpc::RpcClient as _;
use log::{debug, error, warn};
use nssa::AccountId;
use sequencer_core::indexer_client::{IndexerClient, IndexerClientTrait as _};
use sequencer_service::SequencerHandle;
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};
use tempfile::TempDir;
use testcontainers::compose::DockerCompose;
use wallet::{WalletCore, config::WalletConfigOverrides};

use crate::{
    BEDROCK_SERVICE_PORT, BEDROCK_SERVICE_WITH_OPEN_PORT, LOGGER, TestContextBuilder, config,
};

unsafe extern "C" {
    fn start_indexer(config_path: *const c_char, port: u16) -> InitializedIndexerServiceFFIResult;
}

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

        let (bedrock_compose, bedrock_addr) = runtime.block_on(Self::setup_bedrock_node())?;

        let (indexer_ffi, temp_indexer_dir) = Self::setup_indexer_ffi(bedrock_addr, initial_data)
            .context("Failed to setup Indexer")?;

        let (sequencer_handle, temp_sequencer_dir) = runtime
            .block_on(Self::setup_sequencer(
                sequencer_partial_config,
                bedrock_addr,
                // SAFETY: addr is valid if indexer_ffi is valid.
                unsafe { indexer_ffi.addr() },
                initial_data,
            ))
            .context("Failed to setup Sequencer")?;

        let (wallet, temp_wallet_dir, wallet_password) = runtime
            .block_on(Self::setup_wallet(sequencer_handle.addr(), initial_data))
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

    async fn setup_bedrock_node() -> Result<(DockerCompose, SocketAddr)> {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let bedrock_compose_path =
            PathBuf::from(manifest_dir).join("../bedrock/docker-compose.yml");

        let mut compose = DockerCompose::with_auto_client(&[bedrock_compose_path])
            .await
            .context("Failed to setup docker compose for Bedrock")?
            // Setting port to 0 to avoid conflicts between parallel tests, actual port will be retrieved after container is up
            .with_env("PORT", "0");

        #[expect(
            clippy::items_after_statements,
            reason = "This is more readable is this function used just after its definition"
        )]
        async fn up_and_retrieve_port(compose: &mut DockerCompose) -> Result<u16> {
            compose
                .up()
                .await
                .context("Failed to bring up Bedrock services")?;
            let container = compose
                .service(BEDROCK_SERVICE_WITH_OPEN_PORT)
                .with_context(|| {
                    format!(
                        "Failed to get Bedrock service container `{BEDROCK_SERVICE_WITH_OPEN_PORT}`"
                    )
                })?;

            let ports = container.ports().await.with_context(|| {
                format!(
                    "Failed to get ports for Bedrock service container `{}`",
                    container.id()
                )
            })?;
            ports
                .map_to_host_port_ipv4(BEDROCK_SERVICE_PORT)
                .with_context(|| {
                    format!(
                        "Failed to retrieve host port of {BEDROCK_SERVICE_PORT} container \
                        port for container `{}`, existing ports: {ports:?}",
                        container.id()
                    )
                })
        }

        let mut port = None;
        let mut attempt = 0_u32;
        let max_attempts = 5_u32;
        while port.is_none() && attempt < max_attempts {
            attempt = attempt
                .checked_add(1)
                .expect("We check that attempt < max_attempts, so this won't overflow");
            match up_and_retrieve_port(&mut compose).await {
                Ok(p) => {
                    port = Some(p);
                }
                Err(err) => {
                    warn!(
                        "Failed to bring up Bedrock services: {err:?}, attempt {attempt}/{max_attempts}"
                    );
                }
            }
        }
        let Some(port) = port else {
            bail!("Failed to bring up Bedrock services after {max_attempts} attempts");
        };

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        Ok((compose, addr))
    }

    fn setup_indexer_ffi(
        bedrock_addr: SocketAddr,
        initial_data: &config::InitialData,
    ) -> Result<(IndexerServiceFFI, TempDir)> {
        let temp_indexer_dir =
            tempfile::tempdir().context("Failed to create temp dir for indexer home")?;

        debug!(
            "Using temp indexer home at {}",
            temp_indexer_dir.path().display()
        );

        let indexer_config = config::indexer_config(
            bedrock_addr,
            temp_indexer_dir.path().to_owned(),
            initial_data,
        )
        .context("Failed to create Indexer config")?;

        let config_json = serde_json::to_vec(&indexer_config)?;
        let config_path = temp_indexer_dir.path().join("indexer_config.json");
        let mut file = File::create(config_path.as_path())?;
        file.write_all(&config_json)?;
        file.flush()?;

        let res =
            // SAFETY: lib function ensures validity of value.
            unsafe { start_indexer(CString::new(config_path.to_str().unwrap())?.as_ptr(), 0) };

        if res.error.is_error() {
            anyhow::bail!("Indexer FFI error {:?}", res.error);
        }

        Ok((
            // SAFETY: lib function ensures validity of value.
            unsafe { std::ptr::read(res.value) },
            temp_indexer_dir,
        ))
    }

    async fn setup_sequencer(
        partial: config::SequencerPartialConfig,
        bedrock_addr: SocketAddr,
        indexer_addr: SocketAddr,
        initial_data: &config::InitialData,
    ) -> Result<(SequencerHandle, TempDir)> {
        let temp_sequencer_dir =
            tempfile::tempdir().context("Failed to create temp dir for sequencer home")?;

        debug!(
            "Using temp sequencer home at {}",
            temp_sequencer_dir.path().display()
        );

        let config = config::sequencer_config(
            partial,
            temp_sequencer_dir.path().to_owned(),
            bedrock_addr,
            indexer_addr,
            initial_data,
        )
        .context("Failed to create Sequencer config")?;

        let sequencer_handle = sequencer_service::run(config, 0).await?;

        Ok((sequencer_handle, temp_sequencer_dir))
    }

    async fn setup_wallet(
        sequencer_addr: SocketAddr,
        initial_data: &config::InitialData,
    ) -> Result<(WalletCore, TempDir, String)> {
        let config = config::wallet_config(sequencer_addr, initial_data)
            .context("Failed to create Wallet config")?;
        let config_serialized =
            serde_json::to_string_pretty(&config).context("Failed to serialize Wallet config")?;

        let temp_wallet_dir =
            tempfile::tempdir().context("Failed to create temp dir for wallet home")?;

        let config_path = temp_wallet_dir.path().join("wallet_config.json");
        std::fs::write(&config_path, config_serialized)
            .context("Failed to write wallet config in temp dir")?;

        let storage_path = temp_wallet_dir.path().join("storage.json");
        let config_overrides = WalletConfigOverrides::default();

        let wallet_password = "test_pass".to_owned();
        let (wallet, _mnemonic) = WalletCore::new_init_storage(
            config_path,
            storage_path,
            Some(config_overrides),
            &wallet_password,
        )
        .context("Failed to init wallet")?;
        wallet
            .store_persistent_data()
            .await
            .context("Failed to store wallet persistent data")?;

        Ok((wallet, temp_wallet_dir, wallet_password))
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
    pub const fn runtime(&self) -> &Arc<tokio::runtime::Runtime> {
        &self.runtime
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
