//! This library contains common code for integration tests.

use std::{net::SocketAddr, path::PathBuf, sync::LazyLock};

use anyhow::{Context as _, Result, bail};
use common::{HashType, transaction::NSSATransaction};
use futures::FutureExt as _;
use indexer_service::IndexerHandle;
use log::{debug, error, warn};
use nssa::{AccountId, PrivacyPreservingTransaction};
use nssa_core::Commitment;
use sequencer_core::indexer_client::{IndexerClient, IndexerClientTrait as _};
use sequencer_service::SequencerHandle;
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};
use tempfile::TempDir;
use testcontainers::compose::DockerCompose;
use wallet::{WalletCore, config::WalletConfigOverrides};

pub mod config;

// TODO: Remove this and control time from tests
pub const TIME_TO_WAIT_FOR_BLOCK_SECONDS: u64 = 12;
pub const NSSA_PROGRAM_FOR_TEST_DATA_CHANGER: &str = "data_changer.bin";
pub const NSSA_PROGRAM_FOR_TEST_NOOP: &str = "noop.bin";

const BEDROCK_SERVICE_WITH_OPEN_PORT: &str = "logos-blockchain-node-0";
const BEDROCK_SERVICE_PORT: u16 = 18080;

static LOGGER: LazyLock<()> = LazyLock::new(env_logger::init);

/// Test context which sets up a sequencer and a wallet for integration tests.
///
/// It's memory and logically safe to create multiple instances of this struct in parallel tests,
/// as each instance uses its own temporary directories for sequencer and wallet data.
// NOTE: Order of fields is important for proper drop order.
pub struct TestContext {
    sequencer_client: SequencerClient,
    indexer_client: IndexerClient,
    wallet: WalletCore,
    wallet_password: String,
    /// Optional to move out value in Drop.
    sequencer_handle: Option<SequencerHandle>,
    indexer_handle: IndexerHandle,
    bedrock_compose: DockerCompose,
    _temp_indexer_dir: TempDir,
    _temp_sequencer_dir: TempDir,
    _temp_wallet_dir: TempDir,
}

impl TestContext {
    /// Create new test context.
    pub async fn new() -> Result<Self> {
        Self::builder().build().await
    }

    #[must_use]
    pub const fn builder() -> TestContextBuilder {
        TestContextBuilder::new()
    }

    async fn new_configured(
        sequencer_partial_config: config::SequencerPartialConfig,
        initial_data: config::InitialData,
    ) -> Result<Self> {
        // Ensure logger is initialized only once
        *LOGGER;

        debug!("Test context setup");

        let (bedrock_compose, bedrock_addr) = Self::setup_bedrock_node().await?;

        let (indexer_handle, temp_indexer_dir) = Self::setup_indexer(bedrock_addr, &initial_data)
            .await
            .context("Failed to setup Indexer")?;

        let (sequencer_handle, temp_sequencer_dir) = Self::setup_sequencer(
            sequencer_partial_config,
            bedrock_addr,
            indexer_handle.addr(),
            &initial_data,
        )
        .await
        .context("Failed to setup Sequencer")?;

        let (wallet, temp_wallet_dir, wallet_password) =
            Self::setup_wallet(sequencer_handle.addr(), &initial_data)
                .await
                .context("Failed to setup wallet")?;

        let sequencer_url = config::addr_to_url(config::UrlProtocol::Http, sequencer_handle.addr())
            .context("Failed to convert sequencer addr to URL")?;
        let indexer_url = config::addr_to_url(config::UrlProtocol::Ws, indexer_handle.addr())
            .context("Failed to convert indexer addr to URL")?;
        let sequencer_client = SequencerClientBuilder::default()
            .build(sequencer_url)
            .context("Failed to create sequencer client")?;
        let indexer_client = IndexerClient::new(&indexer_url)
            .await
            .context("Failed to create indexer client")?;

        Ok(Self {
            sequencer_client,
            indexer_client,
            wallet,
            wallet_password,
            bedrock_compose,
            sequencer_handle: Some(sequencer_handle),
            indexer_handle,
            _temp_indexer_dir: temp_indexer_dir,
            _temp_sequencer_dir: temp_sequencer_dir,
            _temp_wallet_dir: temp_wallet_dir,
        })
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

    async fn setup_indexer(
        bedrock_addr: SocketAddr,
        initial_data: &config::InitialData,
    ) -> Result<(IndexerHandle, TempDir)> {
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

        indexer_service::run_server(indexer_config, 0)
            .await
            .context("Failed to run Indexer Service")
            .map(|handle| (handle, temp_indexer_dir))
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
}

impl Drop for TestContext {
    fn drop(&mut self) {
        let Self {
            sequencer_handle,
            indexer_handle,
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

        if !indexer_handle.is_healthy() {
            error!("Indexer handle has unexpectedly stopped before TestContext drop");
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

/// A test context to be used in normal #[test] tests.
pub struct BlockingTestContext {
    ctx: Option<TestContext>,
    runtime: tokio::runtime::Runtime,
}

impl BlockingTestContext {
    pub fn new() -> Result<Self> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let ctx = runtime.block_on(TestContext::new())?;
        Ok(Self {
            ctx: Some(ctx),
            runtime,
        })
    }

    pub const fn ctx(&self) -> &TestContext {
        self.ctx.as_ref().expect("TestContext is set")
    }
}

pub struct TestContextBuilder {
    initial_data: Option<config::InitialData>,
    sequencer_partial_config: Option<config::SequencerPartialConfig>,
}

impl TestContextBuilder {
    const fn new() -> Self {
        Self {
            initial_data: None,
            sequencer_partial_config: None,
        }
    }

    #[must_use]
    pub fn with_initial_data(mut self, initial_data: config::InitialData) -> Self {
        self.initial_data = Some(initial_data);
        self
    }

    #[must_use]
    pub const fn with_sequencer_partial_config(
        mut self,
        sequencer_partial_config: config::SequencerPartialConfig,
    ) -> Self {
        self.sequencer_partial_config = Some(sequencer_partial_config);
        self
    }

    pub async fn build(self) -> Result<TestContext> {
        TestContext::new_configured(
            self.sequencer_partial_config.unwrap_or_default(),
            self.initial_data.unwrap_or_else(|| {
                config::InitialData::with_two_public_and_two_private_initialized_accounts()
            }),
        )
        .await
    }
}

impl Drop for BlockingTestContext {
    fn drop(&mut self) {
        let Self { ctx, runtime } = self;

        // Ensure async cleanup of TestContext by blocking on its drop in the runtime.
        runtime.block_on(async {
            if let Some(ctx) = ctx.take() {
                drop(ctx);
            }
        });
    }
}

#[must_use]
pub fn format_public_account_id(account_id: AccountId) -> String {
    format!("Public/{account_id}")
}

#[must_use]
pub fn format_private_account_id(account_id: AccountId) -> String {
    format!("Private/{account_id}")
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "We want the code to panic if the transaction type is not PrivacyPreserving"
)]
pub async fn fetch_privacy_preserving_tx(
    seq_client: &SequencerClient,
    tx_hash: HashType,
) -> PrivacyPreservingTransaction {
    let tx = seq_client.get_transaction(tx_hash).await.unwrap().unwrap();

    match tx {
        NSSATransaction::PrivacyPreserving(privacy_preserving_transaction) => {
            privacy_preserving_transaction
        }
        _ => panic!("Invalid tx type"),
    }
}

pub async fn verify_commitment_is_in_state(
    commitment: Commitment,
    seq_client: &SequencerClient,
) -> bool {
    seq_client
        .get_proof_for_commitment(commitment)
        .await
        .ok()
        .flatten()
        .is_some()
}
