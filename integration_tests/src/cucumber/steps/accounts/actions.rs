use cucumber::{gherkin::Step, given};
use lee::Account;
use log::{error, warn};
use sequencer_service_rpc::RpcClient as _;

use super::super::log_step;
use crate::cucumber::{
    error::{StepError, StepResult},
    world::CucumberWorld,
};

#[given("a new public account")]
async fn create_new_public_account(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let context = world.lez()?;
    let account = context.new_public_account().await?;
    match context.sequencer_client().get_account(account).await {
        Ok(state) if state == Account::default() => {}
        Ok(state) => {
            warn!(
                "Cucumber step '{}' found non-default state for fresh public account {account:?}",
                step.value
            );
            return Err(StepError::AssertionFailed {
                message: format!(
                    "new public account {account:?} already has sequencer state: {state:?}"
                ),
            });
        }
        Err(error) => {
            error!(
                "Cucumber step '{}' failed to query fresh public account {account:?}: {error}",
                step.value
            );
            return Err(StepError::QueryFailed {
                message: format!("failed to query fresh public account {account:?}: {error}"),
            });
        }
    }
    world.environment.new_public_account = Some(account);
    Ok(())
}
