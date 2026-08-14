use common::transaction::LeeTransaction;
use cucumber::{gherkin::Step, then};
use lee_core::account::Nonce;
use sequencer_service_rpc::RpcClient as _;

use super::{
    super::log_step,
    helpers::{
        assert_transaction_kind, expected_public_signing_key, get_transfer_transaction,
        rejected_transfer_details, transfer_artifact, transfer_details,
    },
};
use crate::cucumber::{
    error::{StepError, StepResult},
    steps::transfers::helpers::assert_private_commitment_in_state,
    world::CucumberWorld,
};

fn two_transfer_details(
    world: &CucumberWorld,
    first_name: &str,
    second_name: &str,
    sender: bool,
) -> Result<(lee::AccountId, u128, u128), StepError> {
    let first = transfer_artifact(world, first_name)?;
    let second = transfer_artifact(world, second_name)?;
    let first_account = if sender { first.sender } else { first.receiver };
    let second_account = if sender {
        second.sender
    } else {
        second.receiver
    };
    if first_account != second_account {
        return Err(StepError::AssertionFailed {
            message: format!(
                "transfers '{first_name}' and '{second_name}' do not have the same {} account",
                if sender { "sender" } else { "receiver" }
            ),
        });
    }
    let amount =
        first
            .amount
            .checked_add(second.amount)
            .ok_or_else(|| StepError::AssertionFailed {
                message: format!(
                    "combined amount for transfers '{first_name}' and '{second_name}' overflowed"
                ),
            })?;
    let initial_balance = if sender {
        world.environment.sender_initial_balance
    } else {
        world.environment.receiver_initial_balance
    }
    .ok_or(StepError::MissingObservedBalance)?;
    Ok((first_account, initial_balance, amount))
}

#[then(expr = "the sender balance for transfer {string} decreases by {int}")]
async fn assert_sender_balance_decreased(
    world: &mut CucumberWorld,
    step: &Step,
    transfer_name: String,
    expected_amount: u128,
) -> StepResult {
    log_step(step);
    let (sender, initial_balance, amount) = transfer_details(world, &transfer_name, true)?;
    if amount != expected_amount {
        return Err(StepError::AssertionFailed {
            message: format!(
                "expected sender balance decrease {expected_amount}, got transfer amount {amount}"
            ),
        });
    }
    let observed_balance = world
        .lez()?
        .sequencer_client()
        .get_account_balance(sender)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    let expected_balance =
        initial_balance
            .checked_sub(amount)
            .ok_or_else(|| StepError::AssertionFailed {
                message: format!(
                    "sender initial balance {initial_balance} is below transfer amount {amount}"
                ),
            })?;
    if observed_balance != expected_balance {
        return Err(StepError::AssertionFailed {
            message: format!(
                "sender {sender:?} has balance {observed_balance}, expected {expected_balance}"
            ),
        });
    }
    world.environment.sender_observed_balance = Some(observed_balance);
    Ok(())
}

#[then(expr = "the receiver balance for transfer {string} increases by {int}")]
async fn assert_receiver_balance_increased(
    world: &mut CucumberWorld,
    step: &Step,
    transfer_name: String,
    expected_amount: u128,
) -> StepResult {
    log_step(step);
    let (receiver, initial_balance, amount) = transfer_details(world, &transfer_name, false)?;
    if amount != expected_amount {
        return Err(StepError::AssertionFailed {
            message: format!(
                "expected receiver balance increase {expected_amount}, got transfer amount {amount}"
            ),
        });
    }
    let observed_balance = world
        .lez()?
        .sequencer_client()
        .get_account_balance(receiver)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    let expected_balance =
        initial_balance
            .checked_add(amount)
            .ok_or_else(|| StepError::AssertionFailed {
                message: format!("receiver balance overflow for transfer amount {amount}"),
            })?;
    if observed_balance != expected_balance {
        return Err(StepError::AssertionFailed {
            message: format!(
                "receiver {receiver:?} has balance {observed_balance}, expected {expected_balance}"
            ),
        });
    }
    world.environment.receiver_observed_balance = Some(observed_balance);
    Ok(())
}

#[then(expr = "the sender balance across transfers {string} and {string} decreases by {int}")]
async fn assert_sender_balance_decreased_across_transfers(
    world: &mut CucumberWorld,
    step: &Step,
    first_name: String,
    second_name: String,
    expected_amount: u128,
) -> StepResult {
    log_step(step);
    let (sender, initial_balance, amount) =
        two_transfer_details(world, &first_name, &second_name, true)?;
    if amount != expected_amount {
        return Err(StepError::AssertionFailed {
            message: format!(
                "expected sender balance decrease {expected_amount}, got transfer amount {amount}"
            ),
        });
    }
    let expected_balance =
        initial_balance
            .checked_sub(amount)
            .ok_or_else(|| StepError::AssertionFailed {
                message: format!(
                    "sender initial balance {initial_balance} is below transfer amount {amount}"
                ),
            })?;
    let observed_balance = world
        .lez()?
        .sequencer_client()
        .get_account_balance(sender)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    if observed_balance != expected_balance {
        return Err(StepError::AssertionFailed {
            message: format!(
                "sender {sender:?} has balance {observed_balance}, expected {expected_balance}"
            ),
        });
    }
    world.environment.sender_observed_balance = Some(observed_balance);
    Ok(())
}

#[then(expr = "the receiver balance across transfers {string} and {string} increases by {int}")]
async fn assert_receiver_balance_increased_across_transfers(
    world: &mut CucumberWorld,
    step: &Step,
    first_name: String,
    second_name: String,
    expected_amount: u128,
) -> StepResult {
    log_step(step);
    let (receiver, initial_balance, amount) =
        two_transfer_details(world, &first_name, &second_name, false)?;
    if amount != expected_amount {
        return Err(StepError::AssertionFailed {
            message: format!(
                "expected receiver balance increase {expected_amount}, got transfer amount {amount}"
            ),
        });
    }
    let expected_balance = initial_balance.checked_add(amount).ok_or_else(|| {
        StepError::AssertionFailed {
            message: format!(
                "receiver initial balance {initial_balance} overflowed for transfer amount {amount}"
            ),
        }
    })?;
    let observed_balance = world
        .lez()?
        .sequencer_client()
        .get_account_balance(receiver)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    if observed_balance != expected_balance {
        return Err(StepError::AssertionFailed {
            message: format!(
                "receiver {receiver:?} has balance {observed_balance}, expected {expected_balance}"
            ),
        });
    }
    world.environment.receiver_observed_balance = Some(observed_balance);
    Ok(())
}

#[then(expr = "the new account balance for transfer {string} is {int}")]
async fn assert_new_account_balance(
    world: &mut CucumberWorld,
    step: &Step,
    transfer_name: String,
    expected_balance: u128,
) -> StepResult {
    log_step(step);
    let artifact = transfer_artifact(world, &transfer_name)?;
    let account = world
        .environment
        .new_public_account
        .ok_or(StepError::MissingSelectedAccount)?;
    if artifact.receiver != account {
        return Err(StepError::AssertionFailed {
            message: format!(
                "transfer '{transfer_name}' receiver {:?} is not the new public account {account:?}",
                artifact.receiver
            ),
        });
    }
    let observed_balance = world
        .lez()?
        .sequencer_client()
        .get_account_balance(account)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    if observed_balance != expected_balance {
        return Err(StepError::AssertionFailed {
            message: format!(
                "new public account {account:?} has balance {observed_balance}, expected {expected_balance}"
            ),
        });
    }
    world.environment.receiver_observed_balance = Some(observed_balance);
    Ok(())
}

#[then(expr = "the sender private balance for transfer {string} decreases by {int}")]
async fn assert_sender_private_balance_decreased(
    world: &mut CucumberWorld,
    step: &Step,
    transfer_name: String,
    expected_amount: u128,
) -> StepResult {
    log_step(step);
    let artifact = transfer_artifact(world, &transfer_name)?;
    let account = artifact.sender;
    let initial_balance =
        world
            .environment
            .private_sender_initial_balance
            .ok_or(StepError::MissingObservation {
                field: "private sender initial balance",
            })?;
    let amount = artifact.amount;
    if amount != expected_amount {
        return Err(StepError::AssertionFailed {
            message: format!(
                "expected private sender balance decrease {expected_amount}, got transfer amount {amount}"
            ),
        });
    }
    let expected_balance = initial_balance.checked_sub(amount).ok_or_else(|| {
        StepError::AssertionFailed {
            message: format!(
                "private sender initial balance {initial_balance} is below transfer amount {amount}"
            ),
        }
    })?;
    let observed_balance = world
        .lez()?
        .private_account_balance(account)
        .await?
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("private sender {account:?} has no synchronized wallet balance"),
        })?;
    if observed_balance != expected_balance {
        return Err(StepError::AssertionFailed {
            message: format!(
                "private sender {account:?} has balance {observed_balance}, expected {expected_balance}"
            ),
        });
    }
    world.environment.private_sender_observed_balance = Some(observed_balance);
    Ok(())
}

#[then(expr = "the receiver private balance for transfer {string} increases by {int}")]
async fn assert_receiver_private_balance_increased(
    world: &mut CucumberWorld,
    step: &Step,
    transfer_name: String,
    expected_amount: u128,
) -> StepResult {
    log_step(step);
    let artifact = transfer_artifact(world, &transfer_name)?;
    let account = artifact.receiver;
    let initial_balance = world.environment.private_receiver_initial_balance.ok_or(
        StepError::MissingObservation {
            field: "private receiver initial balance",
        },
    )?;
    let amount = artifact.amount;
    if amount != expected_amount {
        return Err(StepError::AssertionFailed {
            message: format!(
                "expected private receiver balance increase {expected_amount}, got transfer amount {amount}"
            ),
        });
    }
    let expected_balance = initial_balance
        .checked_add(amount)
        .ok_or_else(|| StepError::AssertionFailed {
            message: format!(
                "private receiver initial balance {initial_balance} overflowed for transfer amount {amount}"
            ),
        })?;
    let observed_balance = world
        .lez()?
        .private_account_balance(account)
        .await?
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("private receiver {account:?} has no synchronized wallet balance"),
        })?;
    if observed_balance != expected_balance {
        return Err(StepError::AssertionFailed {
            message: format!(
                "private receiver {account:?} has balance {observed_balance}, expected {expected_balance}"
            ),
        });
    }
    world.environment.private_receiver_observed_balance = Some(observed_balance);
    Ok(())
}

#[then(expr = "the sender private commitment for transfer {string} is in sequencer state")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers receive mutable world references"
)]
async fn assert_sender_private_commitment_in_state(
    world: &mut CucumberWorld,
    step: &Step,
    transfer_name: String,
) -> StepResult {
    log_step(step);
    assert_private_commitment_in_state(world, &transfer_name, true, "sender").await
}

#[then(expr = "the receiver private commitment for transfer {string} is in sequencer state")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers receive mutable world references"
)]
async fn assert_receiver_private_commitment_in_state(
    world: &mut CucumberWorld,
    step: &Step,
    transfer_name: String,
) -> StepResult {
    log_step(step);
    assert_private_commitment_in_state(world, &transfer_name, false, "receiver").await
}

#[then("the transfer is rejected")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
fn assert_transfer_is_rejected(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    if world.environment.transfer_rejection.is_none() {
        return Err(StepError::AssertionFailed {
            message: "expected the insufficient-balance transfer to be rejected".to_owned(),
        });
    }
    Ok(())
}

#[then("no transfer is included in a block")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
fn assert_no_transfer_is_included(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    if world.environment.transfer_rejection.is_none()
        || world.environment.rejected_transfer_sender.is_none()
        || world.environment.rejected_transfer_receiver.is_none()
        || world.environment.rejected_transfer_amount.is_none()
    {
        return Err(StepError::AssertionFailed {
            message: "a rejected transfer must not produce a transaction hash".to_owned(),
        });
    }
    Ok(())
}

#[then("the sender balance remains unchanged")]
async fn assert_sender_balance_unchanged(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let (sender, initial_balance, _) = rejected_transfer_details(world, true)?;
    let observed_balance = world
        .lez()?
        .sequencer_client()
        .get_account_balance(sender)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    if observed_balance != initial_balance {
        return Err(StepError::AssertionFailed {
            message: format!(
                "sender {sender:?} has balance {observed_balance}, expected unchanged balance {initial_balance}"
            ),
        });
    }
    world.environment.sender_observed_balance = Some(observed_balance);
    Ok(())
}

#[then("the receiver balance remains unchanged")]
async fn assert_receiver_balance_unchanged(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let (receiver, initial_balance, _) = rejected_transfer_details(world, false)?;
    let observed_balance = world
        .lez()?
        .sequencer_client()
        .get_account_balance(receiver)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    if observed_balance != initial_balance {
        return Err(StepError::AssertionFailed {
            message: format!(
                "receiver {receiver:?} has balance {observed_balance}, expected unchanged balance {initial_balance}"
            ),
        });
    }
    world.environment.receiver_observed_balance = Some(observed_balance);
    Ok(())
}

#[then(expr = "transfer {string} is included in a block")]
async fn assert_transfer_is_included(
    world: &mut CucumberWorld,
    step: &Step,
    transfer_name: String,
) -> StepResult {
    log_step(step);
    let artifact = transfer_artifact(world, &transfer_name)?;
    let context = world.lez()?;
    let (transaction, block_id) =
        get_transfer_transaction(context.sequencer_client(), artifact.hash).await?;
    assert_transaction_kind(&artifact, &transaction)?;
    world
        .environment
        .transfers
        .get_mut(&transfer_name)
        .ok_or_else(|| StepError::UnknownTransferArtifact {
            name: transfer_name.clone(),
        })?
        .inclusion_block = Some(block_id);
    Ok(())
}

#[then(expr = "only the sender signs transfer {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
async fn assert_only_sender_signs(
    world: &mut CucumberWorld,
    step: &Step,
    transfer_name: String,
) -> StepResult {
    log_step(step);
    let artifact = transfer_artifact(world, &transfer_name)?;
    let sender = artifact.sender;
    let context = world.lez()?;
    let (transaction, _) =
        get_transfer_transaction(context.sequencer_client(), artifact.hash).await?;
    let LeeTransaction::Public(transaction) = transaction else {
        return Err(StepError::AssertionFailed {
            message: "expected the transfer to be public".to_owned(),
        });
    };
    let expected_sender =
        expected_public_signing_key(sender).ok_or_else(|| StepError::QueryFailed {
            message: format!("sender {sender:?} is not in the configured public accounts"),
        })?;
    let signers: Vec<_> = transaction
        .witness_set()
        .signatures_and_public_keys()
        .iter()
        .map(|(_, public_key)| public_key)
        .collect();
    if signers != vec![&expected_sender] {
        return Err(StepError::AssertionFailed {
            message: format!("expected only sender {expected_sender:?} to sign, got {signers:?}"),
        });
    }
    Ok(())
}

#[then(expr = "the sender and new account sign transfer {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
async fn assert_sender_and_new_account_sign(
    world: &mut CucumberWorld,
    step: &Step,
    transfer_name: String,
) -> StepResult {
    log_step(step);
    let artifact = transfer_artifact(world, &transfer_name)?;
    let sender = artifact.sender;
    let receiver = world
        .environment
        .new_public_account
        .ok_or(StepError::MissingSelectedAccount)?;
    let context = world.lez()?;
    let (transaction, _) =
        get_transfer_transaction(context.sequencer_client(), artifact.hash).await?;
    let LeeTransaction::Public(transaction) = transaction else {
        return Err(StepError::AssertionFailed {
            message: "expected the transfer to be public".to_owned(),
        });
    };
    let expected_sender =
        expected_public_signing_key(sender).ok_or_else(|| StepError::QueryFailed {
            message: format!("sender {sender:?} is not in the configured public accounts"),
        })?;
    let expected_receiver = context
        .public_account_signing_key(receiver)
        .await?
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("new account {receiver:?} has no wallet signing key"),
        })?;
    let signers: Vec<_> = transaction
        .witness_set()
        .signatures_and_public_keys()
        .iter()
        .map(|(_, public_key)| public_key)
        .collect();
    if signers != vec![&expected_sender, &expected_receiver] {
        return Err(StepError::AssertionFailed {
            message: format!(
                "expected sender {expected_sender:?} and new account {expected_receiver:?} to sign, got {signers:?}"
            ),
        });
    }
    Ok(())
}

#[then(expr = "only the sender signs transfers {string} and {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
async fn assert_only_sender_signs_both_transfers(
    world: &mut CucumberWorld,
    step: &Step,
    first_name: String,
    second_name: String,
) -> StepResult {
    log_step(step);
    let first = transfer_artifact(world, &first_name)?;
    let second = transfer_artifact(world, &second_name)?;
    let sender = first.sender;
    if second.sender != sender {
        return Err(StepError::AssertionFailed {
            message: "the two transfers have different senders".to_owned(),
        });
    }
    let expected_sender =
        expected_public_signing_key(sender).ok_or_else(|| StepError::QueryFailed {
            message: format!("sender {sender:?} is not in the configured public accounts"),
        })?;
    let context = world.lez()?;
    for (name, artifact) in [(first_name, first), (second_name, second)] {
        let (transaction, _) =
            get_transfer_transaction(context.sequencer_client(), artifact.hash).await?;
        let LeeTransaction::Public(transaction) = transaction else {
            return Err(StepError::AssertionFailed {
                message: format!("transfer '{name}' was not public"),
            });
        };
        let signers: Vec<_> = transaction
            .witness_set()
            .signatures_and_public_keys()
            .iter()
            .map(|(_, public_key)| public_key)
            .collect();
        if signers != vec![&expected_sender] {
            return Err(StepError::AssertionFailed {
                message: format!(
                    "expected only sender {expected_sender:?} to sign transfer '{name}', got {signers:?}"
                ),
            });
        }
    }
    Ok(())
}

#[then(expr = "the sender nonce advances across transfers {string} and {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
async fn assert_sender_nonce_advances(
    world: &mut CucumberWorld,
    step: &Step,
    first_name: String,
    second_name: String,
) -> StepResult {
    log_step(step);
    let first = transfer_artifact(world, &first_name)?;
    let second = transfer_artifact(world, &second_name)?;
    if first.sender != second.sender {
        return Err(StepError::AssertionFailed {
            message: "the two transfers have different senders".to_owned(),
        });
    }
    let sender = first.sender;
    let initial_nonce =
        world
            .environment
            .sender_initial_nonce
            .ok_or(StepError::MissingObservation {
                field: "sender initial nonce",
            })?;
    let expected_nonce =
        Nonce(
            initial_nonce
                .0
                .checked_add(2)
                .ok_or_else(|| StepError::AssertionFailed {
                    message: format!(
                        "sender nonce overflow after two transfers: {initial_nonce:?}"
                    ),
                })?,
        );
    let observed_nonce = world
        .lez()?
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
    if observed_nonce != expected_nonce {
        return Err(StepError::AssertionFailed {
            message: format!(
                "sender {sender:?} nonce is {observed_nonce:?}, expected {expected_nonce:?}"
            ),
        });
    }
    Ok(())
}
