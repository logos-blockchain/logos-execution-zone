use cucumber::gherkin::Step;

pub mod accounts;
pub mod committee;
pub mod environment;
pub mod indexer;
pub mod transfers;

pub const TARGET: &str = "cucumber_steps";

pub(super) fn log_step(step: &Step) {
    tracing::info!(target: TARGET, "Executing Cucumber step: {}", step.value);
}
