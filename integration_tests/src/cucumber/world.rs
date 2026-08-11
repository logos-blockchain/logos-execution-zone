use std::{
    env, fmt,
    fmt::Debug,
    path::{Path, PathBuf},
};

use cucumber::World;
use derivative::Derivative;
use testing_framework_app::{AppHostEnv, AppHostTopology, DeployContext};
use testing_framework_core::scenario::NodeClients;

use crate::{
    cucumber::{
        context::LezScenarioContext,
        default::CUCUMBER_NODE_CONFIG_OVERRIDE,
        error::{StepError, StepResult},
    },
    tf::shutdown_lez_deployment,
};

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

#[derive(Clone, Debug, Default)]
/// Observable account and indexer state recorded during a scenario.
pub struct EnvironmentState {
    /// Account selected for the balance assertion.
    pub selected_account: Option<lee::AccountId>,
    /// Balance returned by the sequencer.
    pub observed_balance: Option<u128>,
    /// Balance configured for the selected account.
    pub expected_balance: Option<u128>,
    /// Last indexer block observed by the convergence step.
    pub observed_indexer_height: Option<u64>,
    /// Sender account for the public transfer scenario.
    pub transfer_sender: Option<lee::AccountId>,
    /// Receiver account for the public transfer scenario.
    pub transfer_receiver: Option<lee::AccountId>,
    /// Fresh recipient account created for the new-account transfer scenario.
    pub new_public_account: Option<lee::AccountId>,
    /// Sender account for the private transfer scenario.
    pub private_transfer_sender: Option<lee::AccountId>,
    /// Receiver account for the private transfer scenario.
    pub private_transfer_receiver: Option<lee::AccountId>,
    /// Amount submitted in the private transfer scenario.
    pub private_transfer_amount: Option<u128>,
    /// Cumulative amount submitted in the public transfer scenario.
    pub transfer_amount: Option<u128>,
    /// Sender balance recorded before the public transfer.
    pub sender_initial_balance: Option<u128>,
    /// Receiver balance recorded before the public transfer.
    pub receiver_initial_balance: Option<u128>,
    /// Sender balance observed after the public transfer.
    pub sender_observed_balance: Option<u128>,
    /// Receiver balance observed after the public transfer.
    pub receiver_observed_balance: Option<u128>,
    /// Sender private balance recorded before the private transfer.
    pub private_sender_initial_balance: Option<u128>,
    /// Receiver private balance recorded before the private transfer.
    pub private_receiver_initial_balance: Option<u128>,
    /// Sender private balance observed after the private transfer.
    pub private_sender_observed_balance: Option<u128>,
    /// Receiver private balance observed after the private transfer.
    pub private_receiver_observed_balance: Option<u128>,
    /// Hash returned for the public transfer.
    pub transfer_hash: Option<common::HashType>,
    /// Block containing the public transfer.
    pub transfer_included_block: Option<u64>,
    /// All transfer hashes submitted in this scenario.
    pub transfer_hashes: Vec<common::HashType>,
    /// Blocks containing the transfers in submission order.
    pub transfer_included_blocks: Vec<u64>,
    /// Sender nonce before the first public transfer.
    pub sender_initial_nonce: Option<lee_core::account::Nonce>,
    /// Error returned when a public transfer is rejected.
    pub transfer_rejection: Option<String>,
}

/// Per-scenario state for Cucumber tests that deploy LEZ applications.
///
/// Cucumber creates a fresh world for each scenario. Its deployment context
/// starts empty; `Given` steps can deploy and expose only the applications the
/// scenario needs. Dropping the world releases all TF-managed resources.
#[derive(World, Derivative)]
#[world(init = Self::default)]
pub struct CucumberWorld {
    /// Testing-framework deployment registry owning exposed application handles.
    pub deployment: DeployContext<AppHostEnv>,
    /// Scenario-owned clones of the LEZ application handles.
    pub lez: Option<LezScenarioContext>,
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
            .field("selected_account", &diagnostic_environment.selected_account)
            .field("observed_balance", &diagnostic_environment.observed_balance)
            .field("expected_balance", &diagnostic_environment.expected_balance)
            .field(
                "observed_indexer_height",
                &diagnostic_environment.observed_indexer_height,
            )
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
