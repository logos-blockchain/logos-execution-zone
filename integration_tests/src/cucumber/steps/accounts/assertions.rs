use cucumber::{gherkin::Step, then};

use super::super::log_step;
use crate::cucumber::{
    error::{StepError, StepResult},
    world::CucumberWorld,
};

#[then("its balance matches the configured initial balance")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
fn assert_first_public_account_balance(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let account = world
        .environment
        .accounts
        .selected_account
        .ok_or(StepError::MissingSelectedAccount)?;
    let observed_balance = world
        .environment
        .accounts
        .observed_balance
        .ok_or(StepError::MissingObservedBalance)?;
    let expected_balance =
        world
            .environment
            .accounts
            .expected_balance
            .ok_or_else(|| StepError::AssertionFailed {
                message: "expected balance was not recorded".to_owned(),
            })?;

    if observed_balance != expected_balance {
        return Err(StepError::AssertionFailed {
            message: format!(
                "account {account:?} has balance {observed_balance}, expected {expected_balance}"
            ),
        });
    }

    Ok(())
}
