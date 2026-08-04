use std::fmt;

use cucumber::World;
use testing_framework_app::{AppHostEnv, AppHostTopology, DeployContext};
use testing_framework_core::scenario::NodeClients;

/// Per-scenario state for Cucumber tests that deploy LEZ applications.
///
/// Cucumber creates a fresh world for each scenario. Its deployment context
/// starts empty; `Given` steps can deploy and expose only the applications the
/// scenario needs. Dropping the world releases all TF-managed resources.
#[derive(World)]
#[world(init = Self::default)]
pub struct LezWorld {
    deployment: DeployContext<AppHostEnv>,
}

impl LezWorld {
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
}

impl Default for LezWorld {
    fn default() -> Self {
        Self {
            deployment: DeployContext::new(AppHostTopology, NodeClients::default()),
        }
    }
}

impl fmt::Debug for LezWorld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LezWorld").finish_non_exhaustive()
    }
}
