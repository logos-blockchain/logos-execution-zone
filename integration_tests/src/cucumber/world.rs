use std::{
    collections::HashMap,
    env, fmt,
    fmt::Debug,
    path::{Path, PathBuf},
};

use cucumber::World;
use testing_framework_app::{AppHostEnv, AppHostTopology, DeployContext};
use testing_framework_core::scenario::NodeClients;

use crate::{
    cucumber::{
        context::{LezScenarioContext, LezSequencerRegistryScenarioContext},
        default::CUCUMBER_NODE_CONFIG_OVERRIDE,
        error::{StepError, StepResult},
    },
    tf::shutdown_lez_deployment,
};

/// Classifies a successful transfer recorded by a Cucumber scenario.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferKind {
    /// A public authenticated transfer.
    Public,
    /// A privacy-preserving authenticated transfer.
    Private,
}

/// Identifies one successful transfer and records the observations needed to
/// assert its lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferArtifact {
    /// Transaction hash returned by the sequencer.
    pub hash: common::HashType,
    /// Sending account.
    pub sender: lee::AccountId,
    /// Receiving account.
    pub receiver: lee::AccountId,
    /// Amount transferred.
    pub amount: u128,
    /// Transaction kind.
    pub kind: TransferKind,
    /// Sender balance observed immediately before submission.
    pub sender_balance_before: u128,
    /// Receiver balance observed immediately before submission.
    pub receiver_balance_before: u128,
    /// Sender nonce observed immediately before submission, when available.
    pub sender_nonce_before: Option<lee_core::account::Nonce>,
    /// Sequencer alias on which the receiver baseline was observed, when it
    /// was intentionally recorded on a different sequencer.
    pub receiver_balance_observer: Option<String>,
    /// Block containing the transaction, once observed.
    pub inclusion_block: Option<u64>,
}

/// Observations staged before a successful transfer artifact can be created.
///
/// The committee scenario records its receiver baseline on one sequencer in a
/// separate step, before submitting the transaction through another sequencer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingTransferObservation {
    /// Receiver whose balance was observed.
    pub receiver: lee::AccountId,
    /// Receiver balance observed before submission.
    pub receiver_balance_before: u128,
    /// Sequencer alias on which the observation was made.
    pub observer_alias: String,
}

/// State retained for a rejected transfer attempt. Rejected attempts do not
/// produce successful transfer artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedTransferAttempt {
    /// Sending account.
    pub sender: lee::AccountId,
    /// Receiving account.
    pub receiver: lee::AccountId,
    /// Amount requested by the rejected transfer.
    pub amount: u128,
    /// Sender balance observed before submission.
    pub sender_balance_before: u128,
    /// Receiver balance observed before submission.
    pub receiver_balance_before: u128,
    /// Sender nonce observed before submission.
    pub sender_nonce_before: lee_core::account::Nonce,
    /// Error returned by the wallet submission.
    pub error: String,
}

/// Successful and rejected transfer observations collected by a scenario.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TransferState {
    /// Successful transfers indexed by their scenario-provided names.
    pub artifacts: HashMap<String, TransferArtifact>,
    /// Baseline recorded before a committee transfer is submitted.
    pub pending_observation: Option<PendingTransferObservation>,
    /// The latest rejected transfer attempt, if one was made.
    pub rejected: Option<RejectedTransferAttempt>,
}

/// Lifecycle state recorded for explicit and fallback runtime teardown.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum RuntimeTeardownState {
    /// No teardown attempt has started.
    #[default]
    NotAttempted,
    /// All exposed LEZ services stopped successfully.
    Succeeded,
    /// Teardown failed; the original diagnostic is retained for later calls.
    Failed(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Committee configuration declared by a multi-sequencer Cucumber scenario.
pub struct CommitteeConfiguration {
    /// Alias of the sequencer that declares the configuration.
    pub leader_alias: String,
    /// Registered aliases authorized in the founding committee.
    pub authorized_sequencers: Vec<String>,
}

/// Account observations recorded during a scenario.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccountState {
    /// Account selected for the balance assertion.
    pub selected_account: Option<lee::AccountId>,
    /// Balance returned by the sequencer.
    pub observed_balance: Option<u128>,
    /// Balance configured for the selected account.
    pub expected_balance: Option<u128>,
    /// Fresh recipient account created for the new-account transfer scenario.
    pub new_public_account: Option<lee::AccountId>,
    /// Sender balance observed after the public transfer.
    pub sender_observed_balance: Option<u128>,
    /// Receiver balance observed after the public transfer.
    pub receiver_observed_balance: Option<u128>,
    /// Sender private balance observed after the private transfer.
    pub private_sender_observed_balance: Option<u128>,
    /// Receiver private balance observed after the private transfer.
    pub private_receiver_observed_balance: Option<u128>,
    /// Label assigned to the public transfer sender.
    pub public_sender_label: Option<String>,
    /// Label assigned to the public transfer receiver.
    pub public_receiver_label: Option<String>,
}

/// Indexer observations recorded during a scenario.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexerState {
    /// Last indexer block observed by a generic convergence step.
    pub observed_height: Option<u64>,
    /// Sequencer height used as the committee indexer convergence target.
    pub committee_target_height: Option<u64>,
    /// Actual indexer finalized height reached during committee convergence.
    pub committee_finalized_height: Option<u64>,
}

/// Committee observations recorded during a multi-sequencer scenario.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommitteeState {
    /// Source sequencer height recorded when another sequencer joins.
    pub committee_join_height: Option<u64>,
    /// Target height reached during the committee rotation phase.
    pub committee_rotation_target: Option<u64>,
    /// Committee configuration declared before sequencer startup.
    pub committee_configuration: Option<CommitteeConfiguration>,
}

/// Observable state recorded during a scenario.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EnvironmentState {
    /// Account observations.
    pub accounts: AccountState,
    /// Transfer artifacts and transfer attempts.
    pub transfers: TransferState,
    /// Indexer observations.
    pub indexer: IndexerState,
    /// Multi-sequencer committee observations.
    pub committee: CommitteeState,
}

/// Per-scenario state for Cucumber tests that deploy LEZ applications.
///
/// Cucumber creates a fresh world for each scenario. Its deployment context
/// starts empty; `Given` steps can deploy and expose only the applications the
/// scenario needs. Dropping the world releases all TF-managed resources.
#[derive(World)]
#[world(init = Self::default)]
pub struct CucumberWorld {
    /// Testing-framework deployment registry owning exposed application handles.
    pub deployment: DeployContext<AppHostEnv>,
    /// Scenario-owned clones of the LEZ application handles.
    pub lez: Option<LezScenarioContext>,
    /// Scenario-owned view of the multi-sequencer registry.
    pub sequencer_registry: Option<LezSequencerRegistryScenarioContext>,
    /// Runtime observations collected by scenario steps.
    pub environment: EnvironmentState,
    /// A unique per-scenario context string used to isolate runtime resources.
    pub test_context: Option<String>,
    /// Base directory for scenario artifacts like logs and generated configs.
    pub scenario_base_dir: PathBuf,
    /// If set, nodes use a `DeploymentSettings` loaded from disk
    /// bypassing generated genesis/test deployment.
    pub deployment_config_override_path: Option<PathBuf>,
    /// Sticky state shared by explicit and fallback runtime teardown.
    pub runtime_teardown: RuntimeTeardownState,
    /// Runtime observations preserved while releasing scenario handles.
    pub teardown_environment: Option<EnvironmentState>,
}

impl CucumberWorld {
    /// Returns the application deployment context for querying exposed
    /// handles.
    #[must_use]
    pub const fn deployment(&self) -> &DeployContext<AppHostEnv> {
        &self.deployment
    }

    /// Returns the application deployment context used by setup steps to
    /// deploy and expose applications.
    #[must_use]
    pub const fn deployment_mut(&mut self) -> &mut DeployContext<AppHostEnv> {
        &mut self.deployment
    }

    /// Returns the unique per-scenario context string used to isolate runtime resources.
    #[must_use]
    pub fn test_context(&self) -> String {
        self.test_context.clone().unwrap_or_default()
    }

    /// Returns the deployed LEZ handles, or a typed error before setup.
    pub fn lez(&self) -> Result<&LezScenarioContext, StepError> {
        self.lez.as_ref().ok_or(StepError::FixtureNotDeployed)
    }

    /// Stores the deployed LEZ handles, rejecting duplicate setup.
    pub fn set_lez(&mut self, context: LezScenarioContext) -> StepResult {
        if self.lez.is_some() {
            return Err(StepError::FixtureAlreadyDeployed);
        }

        self.lez = Some(context);
        Ok(())
    }

    /// Stores the specialized sequencer registry context, rejecting duplicate setup.
    pub fn set_sequencer_registry(
        &mut self,
        context: LezSequencerRegistryScenarioContext,
    ) -> StepResult {
        if self.sequencer_registry.is_some() || self.lez.is_some() {
            return Err(StepError::FixtureAlreadyDeployed);
        }

        self.sequencer_registry = Some(context);
        Ok(())
    }

    /// Returns the deployed sequencer registry context, or a typed error before setup.
    pub fn sequencer_registry(&self) -> Result<&LezSequencerRegistryScenarioContext, StepError> {
        self.sequencer_registry
            .as_ref()
            .ok_or(StepError::FixtureNotDeployed)
    }

    /// Stop all runtime services and release both scenario and registry-owned
    /// handles. This is intentionally explicit because artifact cleanup must
    /// never race a still-running LEZ service.
    pub async fn stop_runtime(&mut self) -> StepResult {
        match &self.runtime_teardown {
            RuntimeTeardownState::NotAttempted => {}
            RuntimeTeardownState::Succeeded => return Ok(()),
            RuntimeTeardownState::Failed(message) => {
                return Err(StepError::TeardownFailed {
                    message: message.clone(),
                });
            }
        }

        let observations = self.environment.clone();
        drop(self.lez.take());
        drop(self.sequencer_registry.take());

        let shutdown_result = shutdown_lez_deployment(&self.deployment).await;
        let deployment = std::mem::replace(
            &mut self.deployment,
            DeployContext::new(AppHostTopology, NodeClients::default()),
        );
        drop(deployment);
        self.teardown_environment = Some(observations);
        self.environment = EnvironmentState::default();

        match shutdown_result {
            Ok(()) => {
                self.runtime_teardown = RuntimeTeardownState::Succeeded;
                Ok(())
            }
            Err(error) => {
                let message = error.to_string();
                self.runtime_teardown = RuntimeTeardownState::Failed(message.clone());
                Err(StepError::TeardownFailed { message })
            }
        }
    }

    /// Set the directory where scenario artifacts should be stored.
    pub fn set_scenario_base_dir(&mut self, log_dir: &Path) {
        let log_dir = PathBuf::from(log_dir);
        self.scenario_base_dir.clone_from(&log_dir);
    }

    /// Returns the same output as `full_debug_info`, but as an owned `String`.
    #[must_use]
    pub fn full_debug_info_string(&self) -> String {
        struct FullDebugInfo<'ab>(&'ab CucumberWorld);

        impl Debug for FullDebugInfo<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.full_debug_info(f)
            }
        }

        format!("{:?}", FullDebugInfo(self))
    }

    /// Writes a secret-free diagnostic representation of the world.
    pub fn full_debug_info(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        let diagnostic_environment = self
            .teardown_environment
            .as_ref()
            .unwrap_or(&self.environment);
        f.debug_struct("CucumberWorld")
            .field("deployment", &"managed deployment context")
            .field("lez", &self.lez.as_ref().map(|_| "deployed"))
            .field(
                "sequencer_registry",
                &self.sequencer_registry.as_ref().map(|_| "deployed"),
            )
            .field("environment", &self.environment)
            .field(
                "runtime_teardown_attempted",
                &!matches!(&self.runtime_teardown, RuntimeTeardownState::NotAttempted),
            )
            .field(
                "runtime_teardown_completed",
                &matches!(&self.runtime_teardown, RuntimeTeardownState::Succeeded),
            )
            .field("runtime_teardown", &self.runtime_teardown)
            .field(
                "teardown_error",
                &match &self.runtime_teardown {
                    RuntimeTeardownState::Failed(message) => Some(message),
                    RuntimeTeardownState::NotAttempted | RuntimeTeardownState::Succeeded => None,
                },
            )
            .field("accounts", &diagnostic_environment.accounts)
            .field("transfers", &diagnostic_environment.transfers)
            .field("indexer", &diagnostic_environment.indexer)
            .field("committee", &diagnostic_environment.committee)
            .field("test_context", &self.test_context)
            .field("scenario_base_dir", &self.scenario_base_dir)
            .field(
                "deployment_config_override_path",
                &deployment_config_override_path_display(
                    self.deployment_config_override_path.as_ref(),
                ),
            )
            .finish()
    }

    /// Remove all scenario artifacts from the scenario base directory. This is
    /// useful for ensuring a clean state before starting a new scenario.
    pub fn clear_scenario_artifacts(&self) -> StepResult {
        if self.scenario_base_dir.is_dir() {
            std::fs::remove_dir_all(&self.scenario_base_dir).map_err(|e| {
                StepError::LogicalError {
                    message: format!(
                        "Failed to clear scenario artifacts in '{}': {e}",
                        self.scenario_base_dir.display()
                    ),
                }
            })?;
        }
        Ok(())
    }

    /// Helper to set the `deployment_config_override_path` in the world based
    /// on the `CUCUMBER_NODE_CONFIG_OVERRIDE` environment variable. This
    /// allows scenarios to specify a custom deployment config on disk that
    /// will be used when starting nodes, bypassing the generated
    /// genesis/test deployment.
    pub fn apply_deployment_config_override_path(&mut self) {
        self.deployment_config_override_path = env::var(CUCUMBER_NODE_CONFIG_OVERRIDE)
            .ok()
            .map(PathBuf::from);
    }

    /// Stores the unique context used to isolate this scenario's resources.
    pub fn set_test_context(&mut self, test_context: String) {
        self.test_context = Some(test_context);
    }
}

impl Default for CucumberWorld {
    fn default() -> Self {
        Self {
            deployment: DeployContext::new(AppHostTopology, NodeClients::default()),
            lez: None,
            sequencer_registry: None,
            environment: EnvironmentState::default(),
            test_context: None,
            scenario_base_dir: PathBuf::default(),
            deployment_config_override_path: None,
            runtime_teardown: RuntimeTeardownState::NotAttempted,
            teardown_environment: None,
        }
    }
}

impl fmt::Debug for CucumberWorld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CucumberWorld").finish_non_exhaustive()
    }
}

fn deployment_config_override_path_display(
    deployment_config_override_path: Option<&PathBuf>,
) -> String {
    deployment_config_override_path.as_ref().map_or_else(
        || "None".to_owned(),
        |path| format!("Some({})", path.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::{CucumberWorld, RuntimeTeardownState};

    #[tokio::test]
    async fn empty_runtime_teardown_is_idempotently_successful() {
        let mut world = CucumberWorld::default();

        world.stop_runtime().await.unwrap();
        world.stop_runtime().await.unwrap();

        assert_eq!(world.runtime_teardown, RuntimeTeardownState::Succeeded);
    }

    #[tokio::test]
    async fn failed_runtime_teardown_state_is_sticky() {
        let mut world = CucumberWorld {
            runtime_teardown: RuntimeTeardownState::Failed("original failure".to_owned()),
            ..CucumberWorld::default()
        };

        let first_error = world.stop_runtime().await.unwrap_err().to_string();
        let second_error = world.stop_runtime().await.unwrap_err().to_string();

        assert_eq!(first_error, "Runtime teardown failed: original failure");
        assert_eq!(second_error, first_error);
        assert_eq!(
            world.runtime_teardown,
            RuntimeTeardownState::Failed("original failure".to_owned())
        );
    }
}
