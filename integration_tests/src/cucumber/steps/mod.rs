use std::{fmt::Display, future::Future, time::Duration};

use cucumber::gherkin::Step;

use super::error::StepError;

pub mod accounts;
pub mod committee;
pub mod environment;
pub mod indexer;
pub mod stake;
pub mod transfers;

pub const TARGET: &str = "cucumber_steps";

pub(super) fn log_step(step: &Step) {
    tracing::info!(target: TARGET, "Executing Cucumber step: {}", step.value);
}

/// Polls `condition` every `poll_interval` until it yields a value, failing
/// with a [`StepError::Timeout`] naming `description` once `timeout` elapses.
pub(crate) async fn wait_until<T, F, Fut>(
    poll_interval: Duration,
    timeout: Duration,
    description: impl Display,
    mut condition: F,
) -> Result<T, StepError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>, StepError>>,
{
    let wait = async {
        loop {
            if let Some(value) = condition().await? {
                return Ok(value);
            }
            tokio::time::sleep(poll_interval).await;
        }
    };
    tokio::time::timeout(timeout, wait)
        .await
        .map_err(|_elapsed| StepError::Timeout {
            message: format!("{description} within {timeout:?}"),
        })?
}
