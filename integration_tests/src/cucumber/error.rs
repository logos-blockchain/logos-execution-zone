use thiserror::Error;

/// Errors reported by Cucumber step implementations.
#[derive(Debug, Error)]
pub enum StepError {
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
    /// No transfer was recorded by an earlier scenario step.
    #[error("No transfer is available")]
    MissingTransfer,
    /// LEZ application deployment failed.
    #[error("Deployment failed: {message}")]
    DeploymentFailed { message: String },
    /// An RPC query failed.
    #[error("Query failed: {message}")]
    QueryFailed { message: String },
    /// A polling operation exceeded its configured timeout.
    #[error("Timed out: {message}")]
    Timeout { message: String },
    /// A scenario assertion did not hold.
    #[error("Assertion failed: {message}")]
    AssertionFailed { message: String },
    /// Runtime teardown failed after the scenario completed or failed.
    #[error("Runtime teardown failed: {message}")]
    TeardownFailed { message: String },
}

/// Result type returned by Cucumber step implementations.
pub type StepResult = Result<(), StepError>;
