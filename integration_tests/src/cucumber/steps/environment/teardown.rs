use cucumber::{gherkin::Step, then};

use super::super::log_step;
use crate::cucumber::{error::StepResult, world::CucumberWorld};

#[then("I stop the runtime")]
async fn stop_runtime(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    world.stop_runtime().await
}
