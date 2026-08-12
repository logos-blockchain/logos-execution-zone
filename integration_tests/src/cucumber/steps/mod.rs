use cucumber::gherkin::Step;

pub mod accounts;
pub mod committee;
pub mod environment;
pub mod indexer;
pub mod transfers;

pub(super) fn log_step(step: &Step) {
    log::debug!("Executing Cucumber step: {}", step.value);
}
