use cucumber::{gherkin::Step, when};
use sequencer_service_rpc::RpcClient as _;

use super::super::log_step;
use crate::cucumber::{
    error::{StepError, StepResult},
    world::CucumberWorld,
};

#[when(expr = "I transfer {int} from the first configured public account to the second")]
async fn transfer_between_configured_public_accounts(
    world: &mut CucumberWorld,
    step: &Step,
    amount: u128,
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
    let sender_initial_balance = context
        .sequencer_client()
        .get_account_balance(sender)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    let receiver_initial_balance = context
        .sequencer_client()
        .get_account_balance(receiver)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    let sender_initial_nonce = context
        .sequencer_client()
        .get_accounts_nonces(vec![sender])
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?
        .into_iter()
        .next()
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("no nonce returned for sender {sender:?}"),
        })?;
    let transfer_hash = context.public_transfer(sender, receiver, amount).await?;

    world.environment.transfer_sender = Some(sender);
    world.environment.transfer_receiver = Some(receiver);
    world.environment.transfer_amount = Some(amount);
    world.environment.sender_initial_balance = Some(sender_initial_balance);
    world.environment.receiver_initial_balance = Some(receiver_initial_balance);
    world.environment.sender_initial_nonce = Some(sender_initial_nonce);
    world.environment.transfer_hash = Some(transfer_hash);
    world.environment.transfer_hashes = vec![transfer_hash];
    Ok(())
}

#[when(expr = "I transfer {int} from the first configured public account to the new account")]
async fn transfer_to_new_public_account(
    world: &mut CucumberWorld,
    step: &Step,
    amount: u128,
) -> StepResult {
    log_step(step);
    let context = world.lez()?;
    let sender = context
        .existing_public_accounts()
        .await?
        .into_iter()
        .next()
        .ok_or(StepError::MissingSelectedAccount)?;
    let receiver = world
        .environment
        .new_public_account
        .ok_or(StepError::MissingSelectedAccount)?;
    let sender_initial_balance = context
        .sequencer_client()
        .get_account_balance(sender)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    let receiver_initial_balance = 0;
    let sender_initial_nonce = context
        .sequencer_client()
        .get_accounts_nonces(vec![sender])
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?
        .into_iter()
        .next()
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("no nonce returned for sender {sender:?}"),
        })?;
    let transfer_hash = context
        .public_transfer_to_new_account(sender, receiver, amount)
        .await?;

    world.environment.transfer_sender = Some(sender);
    world.environment.transfer_receiver = Some(receiver);
    world.environment.transfer_amount = Some(amount);
    world.environment.sender_initial_balance = Some(sender_initial_balance);
    world.environment.receiver_initial_balance = Some(receiver_initial_balance);
    world.environment.sender_initial_nonce = Some(sender_initial_nonce);
    world.environment.transfer_hash = Some(transfer_hash);
    world.environment.transfer_hashes = vec![transfer_hash];
    Ok(())
}

#[when(expr = "I transfer another {int} from the first configured public account to the second")]
async fn transfer_again_between_configured_public_accounts(
    world: &mut CucumberWorld,
    step: &Step,
    amount: u128,
) -> StepResult {
    log_step(step);
    let sender = world
        .environment
        .transfer_sender
        .ok_or(StepError::MissingTransfer)?;
    let receiver = world
        .environment
        .transfer_receiver
        .ok_or(StepError::MissingTransfer)?;
    let previous_amount = world
        .environment
        .transfer_amount
        .ok_or(StepError::MissingTransfer)?;
    let transfer_hash = world
        .lez()?
        .public_transfer(sender, receiver, amount)
        .await?;

    world.environment.transfer_amount = Some(previous_amount.checked_add(amount).ok_or_else(
        || StepError::AssertionFailed {
            message: format!("cumulative transfer amount overflow after {previous_amount}"),
        },
    )?);
    world.environment.transfer_hash = Some(transfer_hash);
    world.environment.transfer_hashes.push(transfer_hash);
    Ok(())
}

#[when(expr = "I attempt to transfer {int} from the first configured public account to the second")]
async fn attempt_insufficient_public_transfer(
    world: &mut CucumberWorld,
    step: &Step,
    amount: u128,
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
    let sender_initial_balance = context
        .sequencer_client()
        .get_account_balance(sender)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    let receiver_initial_balance = context
        .sequencer_client()
        .get_account_balance(receiver)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    let sender_initial_nonce = context
        .sequencer_client()
        .get_accounts_nonces(vec![sender])
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?
        .into_iter()
        .next()
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("no nonce returned for sender {sender:?}"),
        })?;

    let rejection = match context.public_transfer(sender, receiver, amount).await {
        Ok(transfer_hash) => {
            world.environment.transfer_hash = Some(transfer_hash);
            return Err(StepError::AssertionFailed {
                message: format!(
                    "insufficient-balance transfer unexpectedly succeeded with hash {transfer_hash}"
                ),
            });
        }
        Err(error) => error.to_string(),
    };

    world.environment.transfer_sender = Some(sender);
    world.environment.transfer_receiver = Some(receiver);
    world.environment.transfer_amount = Some(amount);
    world.environment.sender_initial_balance = Some(sender_initial_balance);
    world.environment.receiver_initial_balance = Some(receiver_initial_balance);
    world.environment.sender_initial_nonce = Some(sender_initial_nonce);
    world.environment.transfer_rejection = Some(rejection);
    Ok(())
}
