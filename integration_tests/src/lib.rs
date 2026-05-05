//! This library contains common code for integration tests.

use std::{net::SocketAddr, sync::LazyLock};

use anyhow::{Context as _, Result};
use common::{HashType, transaction::NSSATransaction};
use futures::FutureExt as _;
use indexer_service::IndexerHandle;
use log::{debug, error};
use nssa::{AccountId, PrivacyPreservingTransaction};
use nssa_core::Commitment;
use sequencer_core::config::GenesisTransaction;
use sequencer_service::SequencerHandle;
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};
use tempfile::TempDir;
use testcontainers::compose::DockerCompose;
use wallet::{WalletCore, account::AccountIdWithPrivacy, cli::CliAccountMention};

use crate::{
    indexer_client::IndexerClient,
    setup::{
        setup_bedrock_node, setup_indexer, setup_private_accounts_with_initial_supply,
        setup_sequencer, setup_wallet,
    },
};

pub mod config;
pub mod indexer_client;
pub mod setup;

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
    _temp_indexer_dir: Option<TempDir>,
    _temp_sequencer_dir: TempDir,
    _temp_wallet_dir: TempDir,
}

impl TestContext {
    /// Create new test context.
    pub async fn new() -> Result<Self> {
        Self::builder().build().await
    }

    /// Get a builder for the test context to customize its configuration.
    #[must_use]
    pub const fn builder() -> TestContextBuilder {
        TestContextBuilder::new()
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
            .key_chain()
            .public_account_ids()
            .map(|(account_id, _idx)| account_id)
            .collect()
    }

    /// Get existing private account IDs in the wallet.
    #[must_use]
    pub fn existing_private_accounts(&self) -> Vec<AccountId> {
        self.wallet
            .storage()
            .key_chain()
            .private_account_ids()
            .map(|(account_id, _idx)| account_id)
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

pub struct TestContextBuilder {
    genesis_transactions: Option<Vec<GenesisTransaction>>,
    sequencer_partial_config: Option<config::SequencerPartialConfig>,
    indexer_handle: Option<IndexerHandle>,
    bedrock: Option<(DockerCompose, SocketAddr)>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl TestContextBuilder {
    const fn new() -> Self {
        Self {
            genesis_transactions: None,
            sequencer_partial_config: None,
            indexer_handle: None,
            bedrock: None,
            runtime: None,
        }
    }

    #[must_use]
    pub fn with_genesis(mut self, genesis_transactions: Vec<GenesisTransaction>) -> Self {
        self.genesis_transactions = Some(genesis_transactions);
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

    #[must_use]
    pub fn with_bedrock(
        mut self,
        bedrock_compose: DockerCompose,
        bedrock_addr: SocketAddr,
    ) -> Self {
        self.bedrock = Some((bedrock_compose, bedrock_addr));
        self
    }

    #[must_use]
    pub fn with_indexer(mut self, indexer_handle: IndexerHandle) -> Self {
        self.indexer_handle = Some(indexer_handle);
        self
    }

    /// Set custom runtime.
    /// Not used in [`Self::build()`] and only applicable for [`Self::build_blocking()`].
    #[must_use]
    pub fn with_runtime(mut self, runtime: tokio::runtime::Runtime) -> Self {
        self.runtime = Some(runtime);
        self
    }

    pub async fn build(self) -> Result<TestContext> {
        let Self {
            genesis_transactions,
            sequencer_partial_config,
            indexer_handle,
            bedrock,
            runtime: _,
        } = self;

        // Ensure logger is initialized only once
        *LOGGER;

        debug!("Test context setup");

        let (bedrock_compose, bedrock_addr) = match bedrock {
            Some((compose, addr)) => (compose, addr),
            None => setup_bedrock_node().await?,
        };

        let (indexer_handle, temp_indexer_dir) = match indexer_handle {
            Some(handle) => (handle, None),
            None => setup_indexer(bedrock_addr)
                .await
                .map(|(handle, temp_dir)| (handle, Some(temp_dir)))
                .context("Failed to setup Indexer")?,
        };

        let initial_public_accounts = config::default_public_accounts_for_wallet();
        let (sequencer_handle, temp_sequencer_dir) = setup_sequencer(
            sequencer_partial_config.unwrap_or_default(),
            bedrock_addr,
            genesis_transactions
                .unwrap_or_else(|| config::genesis_from_public_accounts(&initial_public_accounts)),
        )
        .await
        .context("Failed to setup Sequencer")?;

        let (mut wallet, temp_wallet_dir, wallet_password) =
            setup_wallet(sequencer_handle.addr(), &initial_public_accounts)
                .context("Failed to setup wallet")?;
        setup_private_accounts_with_initial_supply(&mut wallet)
            .await
            .context("Failed to initialize private accounts in wallet")?;

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

        Ok(TestContext {
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

    pub fn build_blocking(mut self) -> Result<BlockingTestContext> {
        let runtime = self
            .runtime
            .take()
            .unwrap_or_else(|| tokio::runtime::Runtime::new().unwrap());

        let ctx = runtime.block_on(self.build())?;

        Ok(BlockingTestContext {
            ctx: Some(ctx),
            runtime,
        })
    }
}
/// A test context to be used in normal #[test] tests.
pub struct BlockingTestContext {
    ctx: Option<TestContext>,
    runtime: tokio::runtime::Runtime,
}

impl BlockingTestContext {
    pub fn new() -> Result<Self> {
        TestContext::builder().build_blocking()
    }

    pub const fn ctx(&self) -> &TestContext {
        self.ctx.as_ref().expect("TestContext is set")
    }

    pub fn block_on<'ctx, F>(&'ctx self, f: impl FnOnce(&'ctx TestContext) -> F) -> F::Output
    where
        F: std::future::Future + 'ctx,
    {
        let future = f(self.ctx());
        self.runtime.block_on(future)
    }

    pub fn block_on_mut<'ctx, F>(
        &'ctx mut self,
        f: impl FnOnce(&'ctx mut TestContext) -> F,
    ) -> F::Output
    where
        F: std::future::Future + 'ctx,
    {
        let ctx_mut = self.ctx.as_mut().expect("TestContext is set");
        let future = f(ctx_mut);
        self.runtime.block_on(future)
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
pub const fn public_mention(account_id: AccountId) -> CliAccountMention {
    CliAccountMention::Id(AccountIdWithPrivacy::Public(account_id))
}

#[must_use]
pub const fn private_mention(account_id: AccountId) -> CliAccountMention {
    CliAccountMention::Id(AccountIdWithPrivacy::Private(account_id))
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
