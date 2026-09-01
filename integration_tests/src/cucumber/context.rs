use common::HashType;
use lee::AccountId;
use sequencer_service_rpc::SequencerClient;
use testing_framework_app::{AppHostEnv, DeployContext};

use crate::{
    cucumber::error::StepError,
    indexer_client::IndexerClient,
    testing_framework::{
        BedrockCluster, LezIndexerClient, LezRuntime, LezSequencerClient,
        LezSequencerRegistryClient, LezStackHandle,
    },
};

/// Cucumber's view of an already deployed LEZ stack.
///
/// `TestContext` is intentionally not reused here: it owns a separate Docker
/// Compose Bedrock deployment and the complete service lifecycle. The TF
/// applications provide the same low-level setup and deterministic
/// configuration, while this context mirrors only the useful `TestContext` API.
/// Deployment ownership remains in `crate::testing_framework`; Cucumber owns cloned handles
/// and scenario state only.
pub struct LezScenarioContext {
    stack: LezStackHandle,
}

/// Cucumber's view of the TF-owned multi-sequencer registry deployment.
pub struct LezSequencerRegistryScenarioContext {
    bedrock: BedrockCluster,
    indexer: LezIndexerClient,
    registry: LezSequencerRegistryClient,
}

impl LezSequencerRegistryScenarioContext {
    /// Clones the sequencer registry handles exposed by the TF deployment registry.
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
            registry: deployment
                .require::<LezSequencerRegistryClient>()
                .map_err(|error| StepError::MissingComponent {
                    component: "LezSequencerRegistryClient",
                    message: error.to_string(),
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
        self.indexer().client()
    }

    /// Returns the TF-owned sequencer registry handle.
    #[must_use]
    pub const fn registry(&self) -> &LezSequencerRegistryClient {
        &self.registry
    }
}

impl LezScenarioContext {
    /// Creates the Cucumber view from the complete-stack capability returned
    /// by `LezLocalApp::deploy`.
    #[must_use]
    pub const fn from_stack(stack: LezStackHandle) -> Self {
        Self { stack }
    }

    /// Returns the deployed Bedrock cluster handle.
    #[must_use]
    pub const fn bedrock(&self) -> &BedrockCluster {
        self.stack.bedrock()
    }

    /// Returns the deployed LEZ indexer handle.
    #[must_use]
    pub const fn indexer(&self) -> &LezIndexerClient {
        self.stack.indexer()
    }

    /// Returns the JSON-RPC client for the deployed LEZ indexer.
    #[must_use]
    pub fn indexer_client(&self) -> &IndexerClient {
        self.indexer().client()
    }

    /// Returns the deployed LEZ sequencer handle.
    #[must_use]
    pub const fn sequencer(&self) -> &LezSequencerClient {
        self.stack.sequencer()
    }

    /// Returns the JSON-RPC client for the deployed LEZ sequencer.
    #[must_use]
    pub fn sequencer_client(&self) -> &SequencerClient {
        self.sequencer().client()
    }

    /// Returns the deployed LEZ wallet runtime handle.
    #[must_use]
    pub const fn wallet(&self) -> &LezRuntime {
        self.stack.wallet()
    }

    /// Returns the public account IDs currently imported into the wallet.
    pub async fn existing_public_accounts(&self) -> Result<Vec<AccountId>, StepError> {
        self.wallet()
            .existing_public_accounts()
            .await
            .map_err(StepError::query_failed_boxed)
    }

    /// Returns the private account IDs currently imported into the wallet.
    pub async fn existing_private_accounts(&self) -> Result<Vec<AccountId>, StepError> {
        self.wallet()
            .existing_private_accounts()
            .await
            .map_err(StepError::query_failed_boxed)
    }

    /// Returns the locally synchronized balance of an imported private account.
    pub async fn private_account_balance(
        &self,
        account_id: AccountId,
    ) -> Result<Option<u128>, StepError> {
        self.wallet()
            .private_account_balance(account_id)
            .await
            .map_err(StepError::query_failed_boxed)
    }

    /// Returns the current commitment for an imported private account.
    pub async fn private_account_commitment(
        &self,
        account_id: AccountId,
    ) -> Result<Option<lee_core::Commitment>, StepError> {
        self.wallet()
            .private_account_commitment(account_id)
            .await
            .map_err(StepError::query_failed_boxed)
    }

    /// Returns the public signing key for an imported public account.
    pub async fn public_account_signing_key(
        &self,
        account_id: AccountId,
    ) -> Result<Option<lee::PublicKey>, StepError> {
        self.wallet()
            .public_account_signing_key(account_id)
            .await
            .map_err(StepError::query_failed_boxed)
    }

    /// Executes an authenticated transfer between two owned public accounts.
    pub async fn public_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        amount: u128,
    ) -> Result<HashType, StepError> {
        self.wallet()
            .public_transfer(from, to, amount)
            .await
            .map_err(StepError::query_failed_boxed)
    }

    /// Executes an authenticated transfer between two owned private accounts.
    pub async fn private_transfer(
        &self,
        from: AccountId,
        to: AccountId,
        amount: u128,
    ) -> Result<HashType, StepError> {
        self.wallet()
            .private_transfer(from, to, amount)
            .await
            .map_err(StepError::query_failed_boxed)
    }

    /// Synchronizes the wallet with the latest sequencer block.
    pub async fn sync_wallet_to_latest_block(&self) -> Result<(), StepError> {
        self.wallet()
            .sync_to_latest_block()
            .await
            .map_err(StepError::query_failed_boxed)
    }

    /// Creates a fresh public account in the scenario wallet.
    pub async fn new_public_account(&self) -> Result<AccountId, StepError> {
        self.wallet()
            .new_public_account()
            .await
            .map_err(StepError::query_failed_boxed)
    }

    /// Executes an authenticated transfer to a fresh public account, which signs alongside the
    /// sender.
    pub async fn public_transfer_to_new_account(
        &self,
        from: AccountId,
        to: AccountId,
        amount: u128,
    ) -> Result<HashType, StepError> {
        self.wallet()
            .public_transfer_to_new_account(from, to, amount)
            .await
            .map_err(StepError::query_failed_boxed)
    }

    /// Assigns a label to an imported public account through the wallet actor.
    pub async fn set_public_account_label(
        &self,
        account_id: AccountId,
        label: wallet::account::Label,
    ) -> Result<(), StepError> {
        self.wallet()
            .set_public_account_label(account_id, label)
            .await
            .map_err(StepError::query_failed_boxed)
    }

    /// Executes an authenticated public transfer using wallet-resolved labels.
    pub async fn public_transfer_by_labels(
        &self,
        from: wallet::account::Label,
        to: wallet::account::Label,
        amount: u128,
    ) -> Result<HashType, StepError> {
        self.wallet()
            .public_transfer_by_labels(from, to, amount)
            .await
            .map_err(StepError::query_failed_boxed)
    }
}
