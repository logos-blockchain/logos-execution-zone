use cucumber::{gherkin::Step, when};

use super::{
    super::log_step,
    helpers::{ensure_transfer_name_available, insert_transfer_artifact},
};
use crate::cucumber::{
    error::{StepError, StepResult},
    world::{CucumberWorld, TransferArtifact, TransferKind},
};

#[when(
    expr = "I transfer {int} from the first configured private account to the second as {string}"
)]
async fn transfer_between_configured_private_accounts(
    world: &mut CucumberWorld,
    step: &Step,
    amount: u128,
    transfer_name: String,
) -> StepResult {
    log_step(step);
    ensure_transfer_name_available(world, &transfer_name)?;
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

    insert_transfer_artifact(
        world,
        transfer_name,
        TransferArtifact {
            hash: transfer_hash,
            sender,
            receiver,
            amount,
            kind: TransferKind::Private,
            sender_balance_before: sender_initial_balance,
            receiver_balance_before: receiver_initial_balance,
            sender_nonce_before: None,
            receiver_balance_observer: None,
            inclusion_block: None,
        },
    )?;
    Ok(())
}
