use std::path::PathBuf;

use async_trait::async_trait;
use testing_framework_app::{AppDeployment, AppHostEnv, DeployContext};
use testing_framework_core::scenario::DynError;

use super::{BedrockApp, IndexerApp, SequencerApp, WalletApp};
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

/// Root handle indicating that the complete LEZ stack was deployed.
///
/// Component resources are owned by their individually exposed handles in the
/// application runtime registry.
#[derive(Clone, Copy, Debug, Default)]
pub struct LezStackHandle;

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

        let indexer = IndexerApp::new(bedrock.primary_api_addr());
        let indexer = scenario_base_dir.as_ref().map_or_else(
            || indexer.clone(),
            |dir| indexer.clone().with_state_dir(dir.join("lez/indexer")),
        );
        ctx.deploy_and_expose(indexer).await?;

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
        ctx.deploy_and_expose(wallet).await?;

        Ok(LezStackHandle)
    }
}
