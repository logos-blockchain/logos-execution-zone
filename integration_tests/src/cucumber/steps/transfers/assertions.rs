use common::transaction::LeeTransaction;
use cucumber::{gherkin::Step, then};
use lee_core::account::Nonce;
use sequencer_service_rpc::RpcClient as _;

use super::{
    super::log_step,
    helpers::{expected_public_signing_key, get_transfer_transaction, transfer_details},
};
use crate::cucumber::{
    error::{StepError, StepResult},
    steps::transfers::helpers::assert_private_commitment_in_state,
    world::CucumberWorld,
};

#[then(expr = "the sender balance decreases by {int}")]
async fn assert_sender_balance_decreased(
    world: &mut CucumberWorld,
    step: &Step,
    expected_amount: u128,
) -> StepResult {
    log_step(step);
    let (sender, initial_balance, amount) = transfer_details(world, true)?;
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

#[then(expr = "the receiver balance increases by {int}")]
async fn assert_receiver_balance_increased(
    world: &mut CucumberWorld,
    step: &Step,
    expected_amount: u128,
) -> StepResult {
    log_step(step);
    let (receiver, initial_balance, amount) = transfer_details(world, false)?;
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

#[then(expr = "the new account balance is {int}")]
async fn assert_new_account_balance(
    world: &mut CucumberWorld,
    step: &Step,
    expected_balance: u128,
) -> StepResult {
    log_step(step);
    let account = world
        .environment
        .new_public_account
        .ok_or(StepError::MissingSelectedAccount)?;
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

#[then(expr = "the sender private balance decreases by {int}")]
async fn assert_sender_private_balance_decreased(
    world: &mut CucumberWorld,
    step: &Step,
    expected_amount: u128,
) -> StepResult {
    log_step(step);
    let account = world
        .environment
        .private_transfer_sender
        .ok_or(StepError::MissingTransfer)?;
    let initial_balance = world
        .environment
        .private_sender_initial_balance
        .ok_or(StepError::MissingTransfer)?;
    let amount = world
        .environment
        .private_transfer_amount
        .ok_or(StepError::MissingTransfer)?;
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

#[then(expr = "the receiver private balance increases by {int}")]
async fn assert_receiver_private_balance_increased(
    world: &mut CucumberWorld,
    step: &Step,
    expected_amount: u128,
) -> StepResult {
    log_step(step);
    let account = world
        .environment
        .private_transfer_receiver
        .ok_or(StepError::MissingTransfer)?;
    let initial_balance = world
        .environment
        .private_receiver_initial_balance
        .ok_or(StepError::MissingTransfer)?;
    let amount = world
        .environment
        .private_transfer_amount
        .ok_or(StepError::MissingTransfer)?;
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

#[then("the sender private commitment is in sequencer state")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers receive mutable world references"
)]
async fn assert_sender_private_commitment_in_state(
    world: &mut CucumberWorld,
    step: &Step,
) -> StepResult {
    log_step(step);
    assert_private_commitment_in_state(world, true, "sender").await
}

#[then("the receiver private commitment is in sequencer state")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers receive mutable world references"
)]
async fn assert_receiver_private_commitment_in_state(
    world: &mut CucumberWorld,
    step: &Step,
) -> StepResult {
    log_step(step);
    assert_private_commitment_in_state(world, false, "receiver").await
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
        || world.environment.transfer_hash.is_some()
        || !world.environment.transfer_hashes.is_empty()
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
    let (sender, initial_balance, _) = transfer_details(world, true)?;
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
    let (receiver, initial_balance, _) = transfer_details(world, false)?;
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

#[then("the transfer is included in a block")]
async fn assert_transfer_is_included(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let transfer_hash = world
        .environment
        .transfer_hash
        .ok_or(StepError::MissingTransfer)?;
    let (transaction, block_id) = get_transfer_transaction(world.lez()?, transfer_hash).await?;
    if world.environment.private_transfer_sender.is_some()
        && !matches!(transaction, LeeTransaction::PrivacyPreserving(_))
    {
        return Err(StepError::AssertionFailed {
            message: "expected a privacy-preserving private transfer".to_owned(),
        });
    }
    world.environment.transfer_included_block = Some(block_id);
    Ok(())
}

#[then("both transfers are included in blocks")]
async fn assert_both_transfers_are_included(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let hashes = world.environment.transfer_hashes.clone();
    if hashes.len() != 2 {
        return Err(StepError::AssertionFailed {
            message: format!("expected two transfer hashes, got {}", hashes.len()),
        });
    }
    let context = world.lez()?;
    let mut blocks = Vec::with_capacity(hashes.len());
    for transfer_hash in hashes {
        let (_, block_id) = get_transfer_transaction(context, transfer_hash).await?;
        blocks.push(block_id);
    }
    world.environment.transfer_included_blocks = blocks;
    Ok(())
}

#[then("only the sender signs the transfer")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
async fn assert_only_sender_signs(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let sender = world
        .environment
        .transfer_sender
        .ok_or(StepError::MissingTransfer)?;
    let transfer_hash = world
        .environment
        .transfer_hash
        .ok_or(StepError::MissingTransfer)?;
    let (transaction, _) = get_transfer_transaction(world.lez()?, transfer_hash).await?;
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

#[then("the sender and new account sign the transfer")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
async fn assert_sender_and_new_account_sign(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let sender = world
        .environment
        .transfer_sender
        .ok_or(StepError::MissingTransfer)?;
    let receiver = world
        .environment
        .new_public_account
        .ok_or(StepError::MissingSelectedAccount)?;
    let transfer_hash = world
        .environment
        .transfer_hash
        .ok_or(StepError::MissingTransfer)?;
    let context = world.lez()?;
    let (transaction, _) = get_transfer_transaction(context, transfer_hash).await?;
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

#[then("only the sender signs both transfers")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
async fn assert_only_sender_signs_both_transfers(
    world: &mut CucumberWorld,
    step: &Step,
) -> StepResult {
    log_step(step);
    let sender = world
        .environment
        .transfer_sender
        .ok_or(StepError::MissingTransfer)?;
    let hashes = world.environment.transfer_hashes.clone();
    if hashes.len() != 2 {
        return Err(StepError::AssertionFailed {
            message: format!("expected two transfer hashes, got {}", hashes.len()),
        });
    }
    let expected_sender =
        expected_public_signing_key(sender).ok_or_else(|| StepError::QueryFailed {
            message: format!("sender {sender:?} is not in the configured public accounts"),
        })?;
    let context = world.lez()?;
    for transfer_hash in hashes {
        let (transaction, _) = get_transfer_transaction(context, transfer_hash).await?;
        let LeeTransaction::Public(transaction) = transaction else {
            return Err(StepError::AssertionFailed {
                message: format!("transfer {transfer_hash} was not public"),
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
                    "expected only sender {expected_sender:?} to sign transfer {transfer_hash}, got {signers:?}"
                ),
            });
        }
    }
    Ok(())
}

#[then("the sender nonce advances across both transfers")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
async fn assert_sender_nonce_advances(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let sender = world
        .environment
        .transfer_sender
        .ok_or(StepError::MissingTransfer)?;
    let initial_nonce = world
        .environment
        .sender_initial_nonce
        .ok_or(StepError::MissingTransfer)?;
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
