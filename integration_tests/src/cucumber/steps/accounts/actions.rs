use cucumber::{gherkin::Step, given};
use lee::Account;
use sequencer_service_rpc::RpcClient as _;
use tracing::warn;
use wallet::account::Label;

use super::super::{TARGET, log_step};
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
            warn!(target: TARGET,
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
            warn!(target: TARGET,
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

#[given(
    expr = "the configured public accounts have sender label {string} and receiver label {string}"
)]
async fn label_configured_public_accounts(
    world: &mut CucumberWorld,
    step: &Step,
    sender_label: String,
    receiver_label: String,
) -> StepResult {
    log_step(step);
    let context = world.lez()?;
    let accounts = context.existing_public_accounts().await?;
    let sender = accounts
        .first()
        .copied()
        .ok_or(StepError::MissingSelectedAccount)?;
    let receiver = accounts
        .get(1)
        .copied()
        .ok_or(StepError::MissingSelectedAccount)?;
    context
        .set_public_account_label(sender, Label::new(&sender_label))
        .await?;
    context
        .set_public_account_label(receiver, Label::new(&receiver_label))
        .await?;
    world.environment.public_sender_label = Some(sender_label);
    world.environment.public_receiver_label = Some(receiver_label);
    Ok(())
}
