use cucumber::{gherkin::Step, when};
use wallet::account::Label;

use super::{
    super::log_step,
    helpers::{
        ensure_transfer_name_available, insert_transfer_artifact, snapshot_public_sender,
        snapshot_public_transfer,
    },
};
use crate::cucumber::{
    error::{StepError, StepResult},
    world::{CucumberWorld, RejectedTransferAttempt, TransferArtifact, TransferKind},
};

#[when(
    expr = "I transfer {int} from the first configured public account to the second as {string}"
)]
async fn transfer_between_configured_public_accounts(
    world: &mut CucumberWorld,
    step: &Step,
    amount: u128,
    transfer_name: String,
) -> StepResult {
    log_step(step);
    ensure_transfer_name_available(world, &transfer_name)?;
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
    let (sender_initial_balance, receiver_initial_balance, sender_initial_nonce) =
        snapshot_public_transfer(context.sequencer_client(), sender, receiver).await?;
    let transfer_hash = context.public_transfer(sender, receiver, amount).await?;

    insert_transfer_artifact(
        world,
        transfer_name,
        TransferArtifact {
            hash: transfer_hash,
            sender,
            receiver,
            amount,
            kind: TransferKind::Public,
            sender_balance_before: sender_initial_balance,
            receiver_balance_before: receiver_initial_balance,
            sender_nonce_before: Some(sender_initial_nonce),
            receiver_balance_observer: None,
            inclusion_block: None,
        },
    )?;
    Ok(())
}

#[when(expr = "I transfer {int} using the configured public account labels as {string}")]
async fn transfer_between_labeled_public_accounts(
    world: &mut CucumberWorld,
    step: &Step,
    amount: u128,
    transfer_name: String,
) -> StepResult {
    log_step(step);
    ensure_transfer_name_available(world, &transfer_name)?;
    let context = world.lez()?;
    let sender_label = world
        .environment
        .accounts
        .public_sender_label
        .clone()
        .ok_or(StepError::MissingObservation {
            field: "public sender label",
        })?;
    let receiver_label = world
        .environment
        .accounts
        .public_receiver_label
        .clone()
        .ok_or(StepError::MissingObservation {
            field: "public receiver label",
        })?;
    let accounts = context.existing_public_accounts().await?;
    let sender = accounts
        .first()
        .copied()
        .ok_or(StepError::MissingSelectedAccount)?;
    let receiver = accounts
        .get(1)
        .copied()
        .ok_or(StepError::MissingSelectedAccount)?;
    let (sender_initial_balance, receiver_initial_balance, sender_initial_nonce) =
        snapshot_public_transfer(context.sequencer_client(), sender, receiver).await?;
    let transfer_hash = context
        .public_transfer_by_labels(
            Label::new(&sender_label),
            Label::new(&receiver_label),
            amount,
        )
        .await?;

    insert_transfer_artifact(
        world,
        transfer_name,
        TransferArtifact {
            hash: transfer_hash,
            sender,
            receiver,
            amount,
            kind: TransferKind::Public,
            sender_balance_before: sender_initial_balance,
            receiver_balance_before: receiver_initial_balance,
            sender_nonce_before: Some(sender_initial_nonce),
            receiver_balance_observer: None,
            inclusion_block: None,
        },
    )?;
    Ok(())
}

#[when(
    expr = "I transfer {int} from the first configured public account to the new account as {string}"
)]
async fn transfer_to_new_public_account(
    world: &mut CucumberWorld,
    step: &Step,
    amount: u128,
    transfer_name: String,
) -> StepResult {
    log_step(step);
    ensure_transfer_name_available(world, &transfer_name)?;
    let context = world.lez()?;
    let sender = context
        .existing_public_accounts()
        .await?
        .into_iter()
        .next()
        .ok_or(StepError::MissingSelectedAccount)?;
    let receiver = world
        .environment
        .accounts
        .new_public_account
        .ok_or(StepError::MissingSelectedAccount)?;
    let (sender_initial_balance, sender_initial_nonce) =
        snapshot_public_sender(context.sequencer_client(), sender).await?;
    let receiver_initial_balance = 0;
    let transfer_hash = context
        .public_transfer_to_new_account(sender, receiver, amount)
        .await?;

    insert_transfer_artifact(
        world,
        transfer_name,
        TransferArtifact {
            hash: transfer_hash,
            sender,
            receiver,
            amount,
            kind: TransferKind::Public,
            sender_balance_before: sender_initial_balance,
            receiver_balance_before: receiver_initial_balance,
            sender_nonce_before: Some(sender_initial_nonce),
            receiver_balance_observer: None,
            inclusion_block: None,
        },
    )?;
    Ok(())
}

#[when("I attempt to transfer twice the first configured public account balance to the second")]
async fn attempt_insufficient_public_transfer(
    world: &mut CucumberWorld,
    step: &Step,
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
    let (sender_initial_balance, receiver_initial_balance, sender_initial_nonce) =
        snapshot_public_transfer(context.sequencer_client(), sender, receiver).await?;
    let amount =
        sender_initial_balance
            .checked_mul(2)
            .ok_or_else(|| StepError::AssertionFailed {
                message: format!(
                    "sender {sender:?} balance overflowed while building rejection case"
                ),
            })?;

    let rejection = match context
        .wallet()
        .public_transfer_with_failure_kind(sender, receiver, amount)
        .await
    {
        Ok(transfer_hash) => {
            return Err(StepError::AssertionFailed {
                message: format!(
                    "insufficient-balance transfer unexpectedly succeeded with hash {transfer_hash}"
                ),
            });
        }
        Err(wallet::ExecutionFailureKind::InsufficientFundsError) => {
            "InsufficientFundsError".to_owned()
        }
        Err(error) => {
            return Err(StepError::AssertionFailed {
                message: format!(
                    "expected InsufficientFundsError for over-balance transfer, got {error:?}"
                ),
            });
        }
    };

    world.environment.transfers.rejected = Some(RejectedTransferAttempt {
        sender,
        receiver,
        amount,
        sender_balance_before: sender_initial_balance,
        receiver_balance_before: receiver_initial_balance,
        sender_nonce_before: sender_initial_nonce,
        error: rejection,
    });
    Ok(())
}
