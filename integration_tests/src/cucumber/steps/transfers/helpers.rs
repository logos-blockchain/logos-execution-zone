use std::time::Duration;

use common::transaction::LeeTransaction;
use lee::{AccountId, PublicKey};
use lee_core::account::Nonce;
use sequencer_service_rpc::{RpcClient as _, SequencerClient};

use crate::{
    config::default_public_accounts_for_wallet,
    cucumber::{
        error::{StepError, StepResult},
        world::{CucumberWorld, TransferArtifact, TransferKind},
    },
};

pub fn ensure_transfer_name_available(world: &CucumberWorld, name: &str) -> Result<(), StepError> {
    if world.environment.transfers.artifacts.contains_key(name) {
        return Err(StepError::DuplicateTransferArtifact {
            name: name.to_owned(),
        });
    }
    Ok(())
}

pub fn transfer_artifact(world: &CucumberWorld, name: &str) -> Result<TransferArtifact, StepError> {
    world
        .environment
        .transfers
        .artifacts
        .get(name)
        .cloned()
        .ok_or_else(|| StepError::UnknownTransferArtifact {
            name: name.to_owned(),
        })
}

pub fn insert_transfer_artifact(
    world: &mut CucumberWorld,
    name: String,
    artifact: TransferArtifact,
) -> Result<(), StepError> {
    ensure_transfer_name_available(world, &name)?;
    world.environment.transfers.artifacts.insert(name, artifact);
    Ok(())
}

pub fn assert_transaction_kind(
    artifact: &TransferArtifact,
    transaction: &LeeTransaction,
) -> Result<(), StepError> {
    let matches_kind = matches!(
        (artifact.kind, transaction),
        (TransferKind::Public, LeeTransaction::Public(_))
            | (TransferKind::Private, LeeTransaction::PrivacyPreserving(_))
    );
    if !matches_kind {
        return Err(StepError::AssertionFailed {
            message: format!(
                "transfer artifact declared {:?}, but transaction has a different kind",
                artifact.kind
            ),
        });
    }
    Ok(())
}

pub(super) fn expected_balance_after(
    initial_balance: u128,
    amount: u128,
    expected_amount: u128,
    increase: bool,
    role: &str,
) -> Result<u128, StepError> {
    if amount != expected_amount {
        return Err(StepError::AssertionFailed {
            message: format!(
                "expected {role} balance {} by {expected_amount}, got transfer amount {amount}",
                if increase { "increase" } else { "decrease" }
            ),
        });
    }
    if increase {
        initial_balance
            .checked_add(amount)
            .ok_or_else(|| StepError::AssertionFailed {
                message: format!("{role} balance overflow for transfer amount {amount}"),
            })
    } else {
        initial_balance
            .checked_sub(amount)
            .ok_or_else(|| StepError::AssertionFailed {
                message: format!(
                    "{role} initial balance {initial_balance} is below transfer amount {amount}"
                ),
            })
    }
}

pub(super) async fn assert_public_balance_delta(
    world: &CucumberWorld,
    account: AccountId,
    initial_balance: u128,
    transfer_amount: u128,
    expected_amount: u128,
    increase: bool,
    role: &str,
) -> Result<u128, StepError> {
    let expected_balance = expected_balance_after(
        initial_balance,
        transfer_amount,
        expected_amount,
        increase,
        role,
    )?;
    let observed_balance = world
        .lez()?
        .sequencer_client()
        .get_account_balance(account, programs::authenticated_transfer().id())
        .await
        .map_err(StepError::query_failed)?;
    if observed_balance != expected_balance {
        return Err(StepError::AssertionFailed {
            message: format!(
                "{role} {account:?} has balance {observed_balance}, expected {expected_balance}"
            ),
        });
    }
    Ok(observed_balance)
}

pub(super) async fn assert_private_balance_delta(
    world: &CucumberWorld,
    account: AccountId,
    initial_balance: u128,
    transfer_amount: u128,
    expected_amount: u128,
    increase: bool,
    role: &str,
) -> Result<u128, StepError> {
    let expected_balance = expected_balance_after(
        initial_balance,
        transfer_amount,
        expected_amount,
        increase,
        role,
    )?;
    let observed_balance = world
        .lez()?
        .private_account_balance(account)
        .await?
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("{role} {account:?} has no synchronized wallet balance"),
        })?;
    if observed_balance != expected_balance {
        return Err(StepError::AssertionFailed {
            message: format!(
                "{role} {account:?} has balance {observed_balance}, expected {expected_balance}"
            ),
        });
    }
    Ok(observed_balance)
}

pub(super) fn expected_public_signing_key(account: AccountId) -> Option<PublicKey> {
    default_public_accounts_for_wallet()
        .into_iter()
        .find_map(|(private_key, _)| {
            let public_key = PublicKey::new_from_private_key(&private_key);
            (AccountId::from(&public_key) == account).then_some(public_key)
        })
}

pub(super) async fn snapshot_public_sender(
    client: &SequencerClient,
    sender: AccountId,
) -> Result<(u128, Nonce), StepError> {
    let sender_balance = client
        .get_account_balance(sender, programs::authenticated_transfer().id())
        .await
        .map_err(StepError::query_failed)?;
    let sender_nonce = client
        .get_accounts_nonces(vec![sender])
        .await
        .map_err(StepError::query_failed)?
        .into_iter()
        .next()
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("no nonce returned for sender {sender:?}"),
        })?;
    Ok((sender_balance, sender_nonce))
}

pub(super) async fn snapshot_public_transfer(
    client: &SequencerClient,
    sender: AccountId,
    receiver: AccountId,
) -> Result<(u128, u128, Nonce), StepError> {
    let (sender_balance, sender_nonce) = snapshot_public_sender(client, sender).await?;
    let receiver_balance = client
        .get_account_balance(receiver, programs::authenticated_transfer().id())
        .await
        .map_err(StepError::query_failed)?;
    Ok((sender_balance, receiver_balance, sender_nonce))
}

pub(super) fn transfer_details(
    world: &CucumberWorld,
    name: &str,
    sender: bool,
) -> Result<(AccountId, u128, u128), StepError> {
    let artifact = transfer_artifact(world, name)?;
    let account = if sender {
        artifact.sender
    } else {
        artifact.receiver
    };
    let initial_balance = if sender {
        artifact.sender_balance_before
    } else {
        artifact.receiver_balance_before
    };
    Ok((account, initial_balance, artifact.amount))
}

pub(super) fn rejected_transfer_details(
    world: &CucumberWorld,
    sender: bool,
) -> Result<(AccountId, u128, u128), StepError> {
    let rejected =
        world
            .environment
            .transfers
            .rejected
            .as_ref()
            .ok_or(StepError::MissingObservation {
                field: "rejected transfer attempt",
            })?;
    let account = if sender {
        rejected.sender
    } else {
        rejected.receiver
    };
    let initial_balance = if sender {
        rejected.sender_balance_before
    } else {
        rejected.receiver_balance_before
    };
    let amount = rejected.amount;
    Ok((account, initial_balance, amount))
}

pub async fn get_transfer_transaction(
    client: &sequencer_service_rpc::SequencerClient,
    transfer_hash: common::HashType,
) -> Result<(LeeTransaction, u64), StepError> {
    client
        .get_transaction(transfer_hash)
        .await
        .map_err(StepError::query_failed)?
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("transfer {transfer_hash} was not found in the sequencer"),
        })
}

/// Polls a sequencer until a named transfer is included and validates its
/// declared transaction kind at the same observation point.
pub async fn wait_for_transfer_inclusion(
    client: &SequencerClient,
    artifact: &TransferArtifact,
    timeout: Duration,
    description: &str,
) -> Result<u64, StepError> {
    const POLL_INTERVAL: Duration = Duration::from_secs(2);
    let wait = async {
        loop {
            if let Some((transaction, block_id)) = client
                .get_transaction(artifact.hash)
                .await
                .map_err(StepError::query_failed)?
            {
                assert_transaction_kind(artifact, &transaction)?;
                return Ok::<u64, StepError>(block_id);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    };
    tokio::time::timeout(timeout, wait)
        .await
        .map_err(|_elapsed| StepError::Timeout {
            message: format!("{description} within {timeout:?}"),
        })?
}

pub async fn assert_private_commitment_in_state(
    world: &CucumberWorld,
    transfer_name: &str,
    sender: bool,
    role: &str,
) -> StepResult {
    let artifact = transfer_artifact(world, transfer_name)?;
    let account = if sender {
        artifact.sender
    } else {
        artifact.receiver
    };
    let context = world.lez()?;
    let commitment = context
        .private_account_commitment(account)
        .await?
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("private {role} {account:?} has no current commitment"),
        })?;
    if !crate::verify_commitment_is_in_state(commitment, context.sequencer_client()).await {
        return Err(StepError::AssertionFailed {
            message: format!(
                "private {role} commitment for account {account:?} is not in sequencer state"
            ),
        });
    }
    Ok(())
}
