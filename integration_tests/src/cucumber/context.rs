use lee::AccountId;
use sequencer_service_rpc::SequencerClient;
use testing_framework_app::{AppHostEnv, DeployContext};

use crate::{
    cucumber::error::StepError,
    indexer_client::IndexerClient,
    tf::{BedrockCluster, LezIndexerClient, LezRuntime, LezSequencerClient},
};

/// Cucumber's view of an already deployed LEZ stack.
///
/// `TestContext` is intentionally not reused here: it owns a separate Docker
/// Compose Bedrock deployment and the complete service lifecycle. The TF
/// applications provide the same low-level setup and deterministic
/// configuration, while this context mirrors only the useful `TestContext` API.
/// Deployment ownership remains in `crate::tf`; Cucumber owns cloned handles
/// and scenario state only.
pub struct LezScenarioContext {
    bedrock: BedrockCluster,
    indexer: LezIndexerClient,
    sequencer: LezSequencerClient,
    wallet: LezRuntime,
}

impl LezScenarioContext {
    /// Clones the handles exposed by the existing TF deployment registry.
    pub fn from_deployment(deployment: &DeployContext<AppHostEnv>) -> Result<Self, StepError> {
        Ok(Self {
            bedrock: deployment.require::<BedrockCluster>().map_err(|error| {
                StepError::MissingComponent {
                    component: "BedrockCluster",
                    message: error.to_string(),
                }
            })?,
            indexer: deployment.require::<LezIndexerClient>().map_err(|error| {
                StepError::MissingComponent {
                    component: "LezIndexerClient",
                    message: error.to_string(),
                }
            })?,
            sequencer: deployment
                .require::<LezSequencerClient>()
                .map_err(|error| StepError::MissingComponent {
                    component: "LezSequencerClient",
                    message: error.to_string(),
                })?,
            wallet: deployment.require::<LezRuntime>().map_err(|error| {
                StepError::MissingComponent {
                    component: "LezRuntime",
                    message: error.to_string(),
                }
            })?,
        })
    }

    /// Returns the deployed Bedrock cluster handle.
    #[must_use]
    pub const fn bedrock(&self) -> &BedrockCluster {
        &self.bedrock
    }

    /// Returns the deployed LEZ indexer handle.
    #[must_use]
    pub const fn indexer(&self) -> &LezIndexerClient {
        &self.indexer
    }

    /// Returns the JSON-RPC client for the deployed LEZ indexer.
    #[must_use]
    pub fn indexer_client(&self) -> &IndexerClient {
        self.indexer.client()
    }

    /// Returns the deployed LEZ sequencer handle.
    #[must_use]
    pub const fn sequencer(&self) -> &LezSequencerClient {
        &self.sequencer
    }

    /// Returns the JSON-RPC client for the deployed LEZ sequencer.
    #[must_use]
    pub fn sequencer_client(&self) -> &SequencerClient {
        self.sequencer.client()
    }

    /// Returns the deployed LEZ wallet runtime handle.
    #[must_use]
    pub const fn wallet(&self) -> &LezRuntime {
        &self.wallet
    }

    /// Returns the public account IDs currently imported into the wallet.
    pub async fn existing_public_accounts(&self) -> Result<Vec<AccountId>, StepError> {
        self.wallet
            .existing_public_accounts()
            .await
            .map_err(|error| StepError::QueryFailed {
                message: error.to_string(),
            })
    }

    /// Returns the private account IDs currently imported into the wallet.
    pub async fn existing_private_accounts(&self) -> Result<Vec<AccountId>, StepError> {
        self.wallet
            .existing_private_accounts()
            .await
            .map_err(|error| StepError::QueryFailed {
                message: error.to_string(),
            })
    }
}
