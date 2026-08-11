use cucumber::{gherkin::Step, when};

use super::super::log_step;
use crate::cucumber::{
    error::{StepError, StepResult},
    world::CucumberWorld,
};

#[when(expr = "I transfer {int} from the first configured private account to the second")]
async fn transfer_between_configured_private_accounts(
    world: &mut CucumberWorld,
    step: &Step,
    amount: u128,
) -> StepResult {
    log_step(step);
    let context = world.lez()?;
    context.sync_wallet_to_latest_block().await?;
    let accounts = context.existing_private_accounts().await?;
    let sender = accounts
        .first()
        .copied()
        .ok_or_else(|| StepError::AssertionFailed {
            message: "expected at least two configured private accounts, found none".to_owned(),
        })?;
    let receiver = accounts
        .get(1)
        .copied()
        .ok_or_else(|| StepError::AssertionFailed {
            message: format!(
                "expected at least two configured private accounts, found {}",
                accounts.len()
            ),
        })?;
    let sender_initial_balance =
        context
            .private_account_balance(sender)
            .await?
            .ok_or_else(|| StepError::QueryFailed {
                message: format!("private sender {sender:?} has no synchronized wallet balance"),
            })?;
    let receiver_initial_balance = context
        .private_account_balance(receiver)
        .await?
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("private receiver {receiver:?} has no synchronized wallet balance"),
        })?;
    let transfer_hash = context.private_transfer(sender, receiver, amount).await?;

    world.environment.private_transfer_sender = Some(sender);
    world.environment.private_transfer_receiver = Some(receiver);
    world.environment.private_transfer_amount = Some(amount);
    world.environment.private_sender_initial_balance = Some(sender_initial_balance);
    world.environment.private_receiver_initial_balance = Some(receiver_initial_balance);
    world.environment.transfer_hash = Some(transfer_hash);
    world.environment.transfer_hashes = vec![transfer_hash];
    Ok(())
}
