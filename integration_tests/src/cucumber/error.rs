use testing_framework_core::scenario::DynError;
use thiserror::Error;

/// Errors reported by Cucumber step implementations.
#[derive(Debug, Error)]
pub enum StepError {
    /// A Gherkin argument or table value is malformed or out of range.
    #[error("Invalid Cucumber argument: {message}")]
    InvalidArgument { message: String },
    /// A local test-harness or filesystem operation failed.
    #[error("Logical error: {message}")]
    LogicalError { message: String },
    /// The scenario attempted to access the LEZ fixture before deployment.
    #[error("Fixture has not been deployed")]
    FixtureNotDeployed,
    /// The scenario attempted to deploy the LEZ fixture more than once.
    #[error("Fixture has already been deployed")]
    FixtureAlreadyDeployed,
    /// A required component was absent from the deployment registry.
    #[error("Missing {component} from deployment: {message}")]
    MissingComponent {
        /// Name of the component that was requested.
        component: &'static str,
        /// Original deployment-registry diagnostic.
        message: String,
    },
    /// No account was selected by an earlier scenario step.
    #[error("No selected account is available")]
    MissingSelectedAccount,
    /// No account balance was recorded by an earlier scenario step.
    #[error("No observed balance is available")]
    MissingObservedBalance,
    /// A required scenario observation was not recorded by an earlier step.
    #[error("Missing scenario observation: {field}")]
    MissingObservation { field: &'static str },
    /// A named successful transfer does not exist in the scenario registry.
    #[error("Unknown transfer artifact '{name}'")]
    UnknownTransferArtifact { name: String },
    /// A scenario attempted to reuse a successful-transfer artifact name.
    #[error("Duplicate transfer artifact '{name}'")]
    DuplicateTransferArtifact { name: String },
    /// A named transfer has not yet been observed in a block.
    #[error("Transfer artifact '{name}' has no recorded inclusion block")]
    MissingTransferInclusion { name: String },
    /// LEZ application deployment failed.
    #[error("Deployment failed: {message}")]
    DeploymentFailed { message: String },
    /// An operational deployment error with its original source preserved.
    #[error("Deployment failed")]
    DeploymentFailedSource {
        /// Original deployment error.
        #[source]
        source: anyhow::Error,
    },
    /// An RPC query failed.
    #[error("Query failed: {message}")]
    QueryFailed { message: String },
    /// An operational query error with its original source preserved.
    #[error("Query failed")]
    QueryFailedSource {
        /// Original query error.
        #[source]
        source: anyhow::Error,
    },
    /// A polling operation exceeded its configured timeout.
    #[error("Timed out: {message}")]
    Timeout { message: String },
    /// A scenario assertion did not hold.
    #[error("Assertion failed: {message}")]
    AssertionFailed { message: String },
    /// Runtime teardown failed after the scenario completed or failed.
    #[error("Runtime teardown failed: {message}")]
    TeardownFailed { message: String },
    /// An operational teardown error with its original source preserved.
    #[error("Runtime teardown failed")]
    TeardownFailedSource {
        /// Original teardown error.
        #[source]
        source: anyhow::Error,
    },
}

impl StepError {
    /// Retains the source of an operational deployment failure while adding
    /// the scenario-specific context.
    pub fn deployment_failed<E>(error: E, context: impl Into<String>) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::DeploymentFailedSource {
            source: anyhow::Error::new(error).context(context.into()),
        }
    }

    /// Retains a testing-framework boxed deployment error with context.
    pub fn deployment_failed_boxed(error: DynError, context: impl Into<String>) -> Self {
        Self::DeploymentFailedSource {
            source: anyhow::Error::from_boxed(error).context(context.into()),
        }
    }

    /// Retains the source of an operational query failure.
    pub fn query_failed<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::QueryFailedSource {
            source: anyhow::Error::new(error),
        }
    }

    /// Retains a testing-framework boxed query error.
    pub fn query_failed_boxed(error: DynError) -> Self {
        Self::QueryFailedSource {
            source: anyhow::Error::from_boxed(error),
        }
    }
}

/// Result type returned by Cucumber step implementations.
pub type StepResult = Result<(), StepError>;
