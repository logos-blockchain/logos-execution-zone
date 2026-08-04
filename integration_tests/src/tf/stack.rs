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
}

#[async_trait]
impl AppDeployment<AppHostEnv> for LezLocalApp {
    type Handle = LezStackHandle;

    async fn deploy(self, ctx: &mut DeployContext<AppHostEnv>) -> Result<Self::Handle, DynError> {
        let bedrock = ctx.deploy_and_expose(self.bedrock).await?;

        ctx.deploy_and_expose(IndexerApp::new(bedrock.primary_api_addr()))
            .await?;

        let sequencer = ctx
            .deploy_and_expose(SequencerApp::new(
                self.sequencer,
                bedrock.primary_api_addr(),
            ))
            .await?;

        ctx.deploy_and_expose(WalletApp::from_sequencer(&sequencer))
            .await?;

        Ok(LezStackHandle)
    }
}
