use std::{path::PathBuf, time::Duration};

use async_trait::async_trait;
use testing_framework_app::{AppDeployment, AppHostEnv, DeployContext};
use testing_framework_core::scenario::DynError;
use tokio::time::{Instant, sleep};

use super::{BedrockApp, BedrockCluster, IndexerApp, SequencerApp, WalletApp};
use crate::config::SequencerPartialConfig;

/// Complete process-based LEZ stack: Bedrock, indexer, sequencer, and wallet.
#[derive(Clone)]
pub struct LezLocalApp {
    bedrock: BedrockApp,
    sequencer: SequencerPartialConfig,
    scenario_base_dir: Option<PathBuf>,
    initialize_private_accounts: bool,
}

impl Default for LezLocalApp {
    fn default() -> Self {
        Self::new()
    }
}

/// Capability for the complete deployed LEZ stack.
///
/// The same component handles are also exposed individually through the
/// deployment registry so teardown can stop them in dependency order.
#[derive(Clone)]
pub struct LezStackHandle {
    bedrock: BedrockCluster,
    indexer: super::LezIndexerClient,
    sequencer: super::LezSequencerClient,
    wallet: super::LezRuntime,
}

impl LezStackHandle {
    pub(crate) const fn new(
        bedrock: BedrockCluster,
        indexer: super::LezIndexerClient,
        sequencer: super::LezSequencerClient,
        wallet: super::LezRuntime,
    ) -> Self {
        Self {
            bedrock,
            indexer,
            sequencer,
            wallet,
        }
    }

    pub(crate) const fn bedrock(&self) -> &BedrockCluster {
        &self.bedrock
    }

    pub(crate) const fn indexer(&self) -> &super::LezIndexerClient {
        &self.indexer
    }

    pub(crate) const fn sequencer(&self) -> &super::LezSequencerClient {
        &self.sequencer
    }

    pub(crate) const fn wallet(&self) -> &super::LezRuntime {
        &self.wallet
    }
}

impl LezLocalApp {
    /// Creates a complete LEZ deployment with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bedrock: BedrockApp::default(),
            sequencer: SequencerPartialConfig::default(),
            scenario_base_dir: None,
            initialize_private_accounts: true,
        }
    }

    /// Replaces the sequencer configuration used by the stack.
    #[must_use]
    pub const fn with_sequencer_config(mut self, sequencer: SequencerPartialConfig) -> Self {
        self.sequencer = sequencer;
        self
    }

    /// Sets the priority fee used by the LEZ sequencer when publishing to Bedrock.
    #[must_use]
    pub const fn with_priority_fee(mut self, priority_fee: u64) -> Self {
        self.sequencer.priority_fee = priority_fee;
        self
    }

    /// Sets the number of Bedrock nodes in the stack.
    #[must_use]
    pub fn with_bedrock_nodes(mut self, nodes: usize) -> Self {
        self.bedrock = self.bedrock.with_nodes(nodes);
        self
    }

    /// Replaces the stack's Bedrock deployment, including any Logos builder
    /// overrides supplied by the caller.
    #[must_use]
    pub fn with_bedrock(mut self, bedrock: BedrockApp) -> Self {
        self.bedrock = bedrock;
        self
    }

    /// Places every LEZ component below a unique scenario artifact tree.
    #[must_use]
    pub fn with_scenario_base_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.scenario_base_dir = Some(dir.into());
        self
    }

    /// Skip privacy-preserving account funding for a smoke fixture that only
    /// exercises the configured public account and indexer lifecycle.
    #[must_use]
    pub const fn without_private_account_initialization(mut self) -> Self {
        self.initialize_private_accounts = false;
        self
    }
}

#[async_trait]
impl AppDeployment<AppHostEnv> for LezLocalApp {
    type Handle = LezStackHandle;

    async fn deploy(self, ctx: &mut DeployContext<AppHostEnv>) -> Result<Self::Handle, DynError> {
        let scenario_base_dir = self.scenario_base_dir;
        let bedrock_app = scenario_base_dir.as_ref().map_or_else(
            || self.bedrock.clone(),
            |dir| {
                self.bedrock
                    .clone()
                    .with_scenario_base_dir(dir.join("node"))
            },
        );
        let bedrock = ctx.deploy_and_expose(bedrock_app).await?;
        wait_for_bedrock_ready(&bedrock).await?;

        let indexer = IndexerApp::new(bedrock.primary_api_addr());
        let indexer = scenario_base_dir.as_ref().map_or_else(
            || indexer.clone(),
            |dir| indexer.clone().with_state_dir(dir.join("lez/indexer")),
        );
        let indexer = ctx.deploy_and_expose(indexer).await?;

        let sequencer = SequencerApp::new(self.sequencer, bedrock.primary_api_addr());
        let sequencer = scenario_base_dir.as_ref().map_or_else(
            || sequencer.clone(),
            |dir| sequencer.clone().with_state_dir(dir.join("lez/sequencer")),
        );
        let sequencer = ctx.deploy_and_expose(sequencer).await?;

        let wallet = WalletApp::from_sequencer(&sequencer);
        let wallet = if self.initialize_private_accounts {
            wallet
        } else {
            wallet.without_private_account_initialization()
        };
        let wallet = scenario_base_dir.as_ref().map_or_else(
            || wallet.clone(),
            |dir| wallet.clone().with_state_dir(dir.join("lez/wallet")),
        );
        let wallet = ctx.deploy_and_expose(wallet).await?;

        Ok(LezStackHandle::new(bedrock, indexer, sequencer, wallet))
    }
}

async fn wait_for_bedrock_ready(bedrock: &BedrockCluster) -> Result<(), DynError> {
    const TIMEOUT: Duration = Duration::from_secs(60);
    let started = Instant::now();
    let mut last_error = None;

    while started.elapsed() < TIMEOUT {
        match bedrock.cryptarchia_info().await {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error.to_string());
                sleep(Duration::from_secs(1)).await;
            }
        }
    }

    Err(anyhow::anyhow!(
        "Bedrock did not become ready after {TIMEOUT:?}: {}",
        last_error.unwrap_or_else(|| "no readiness response".to_owned())
    )
    .into())
}

/// Stops all exposed LEZ services in dependency order.
///
/// The deployment registry remains owned by the caller and must be dropped
/// after this function returns so Bedrock and its managed state can be
/// released only after the wallet, indexer, and sequencer have stopped.
pub async fn shutdown_lez_deployment(
    deployment: &DeployContext<AppHostEnv>,
) -> Result<(), DynError> {
    let mut failures = Vec::new();

    if let Some(wallet) = deployment.get::<super::LezRuntime>()
        && let Err(error) = wallet.shutdown().await
    {
        failures.push(format!("wallet: {error}"));
    }

    if let Some(indexer) = deployment.get::<super::LezIndexerClient>()
        && let Err(error) = indexer.shutdown().await
    {
        failures.push(format!("indexer: {error}"));
    }

    if let Some(sequencer) = deployment.get::<super::LezSequencerClient>()
        && let Err(error) = sequencer.shutdown().await
    {
        failures.push(format!("sequencer: {error}"));
    }

    if let Some(registry) = deployment.get::<super::LezSequencerRegistryClient>()
        && let Err(error) = registry.shutdown().await
    {
        failures.push(format!("sequencer registry: {error}"));
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("LEZ runtime shutdown failed:\n- {}", failures.join("\n- ")).into())
    }
}
