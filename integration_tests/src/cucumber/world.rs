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
    tf::LezRuntime,
};

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
    /// Whether explicit or fallback runtime teardown has started.
    pub runtime_teardown_attempted: bool,
    /// Whether runtime teardown completed without an error.
    pub runtime_teardown_completed: bool,
    /// Diagnostic text from a failed runtime teardown, if any.
    pub teardown_error: Option<String>,
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
        self.runtime_teardown_attempted = true;
        self.teardown_error = None;

        let runtime = self
            .lez
            .as_ref()
            .map(|context| context.wallet().clone())
            .or_else(|| self.deployment.require::<LezRuntime>().ok());

        let shutdown_result = if let Some(runtime) = runtime {
            runtime.shutdown().await
        } else {
            Ok(())
        };

        // Always release the cloned context and registry-owned handles, even
        // if the wallet actor reports a shutdown error.
        let context = self.lez.take();
        drop(context);
        let deployment = std::mem::replace(
            &mut self.deployment,
            DeployContext::new(AppHostTopology, NodeClients::default()),
        );
        drop(deployment);
        if self.environment.selected_account.is_some()
            || self.environment.observed_balance.is_some()
            || self.environment.expected_balance.is_some()
            || self.environment.observed_indexer_height.is_some()
        {
            self.teardown_environment = Some(self.environment.clone());
        }
        self.environment = EnvironmentState::default();

        match shutdown_result {
            Ok(()) => {
                self.runtime_teardown_completed = true;
                Ok(())
            }
            Err(error) => {
                self.runtime_teardown_completed = false;
                self.teardown_error = Some(error.to_string());
                Err(StepError::TeardownFailed {
                    message: error.to_string(),
                })
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
                &self.runtime_teardown_attempted,
            )
            .field(
                "runtime_teardown_completed",
                &self.runtime_teardown_completed,
            )
            .field("teardown_error", &self.teardown_error)
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
            runtime_teardown_attempted: false,
            runtime_teardown_completed: false,
            teardown_error: None,
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
