use common::transaction::LeeTransaction;
use lee::{AccountId, PublicKey};
use sequencer_service_rpc::RpcClient as _;

use crate::{
    config::default_public_accounts_for_wallet,
    cucumber::{
        error::{StepError, StepResult},
        world::{CucumberWorld, TransferArtifact, TransferKind},
    },
};

pub fn ensure_transfer_name_available(world: &CucumberWorld, name: &str) -> Result<(), StepError> {
    if world.environment.transfers.contains_key(name) {
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
        .get(name)
        .copied()
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
    world.environment.transfers.insert(name, artifact);
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

pub(super) fn expected_public_signing_key(account: AccountId) -> Option<PublicKey> {
    default_public_accounts_for_wallet()
        .into_iter()
        .find_map(|(private_key, _)| {
            let public_key = PublicKey::new_from_private_key(&private_key);
            (AccountId::from(&public_key) == account).then_some(public_key)
        })
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
        world.environment.sender_initial_balance
    } else {
        world.environment.receiver_initial_balance
    }
    .ok_or(StepError::MissingObservation {
        field: if sender {
            "sender initial balance"
        } else {
            "receiver initial balance"
        },
    })?;
    Ok((account, initial_balance, artifact.amount))
}

pub(super) fn rejected_transfer_details(
    world: &CucumberWorld,
    sender: bool,
) -> Result<(AccountId, u128, u128), StepError> {
    let account = if sender {
        world.environment.rejected_transfer_sender
    } else {
        world.environment.rejected_transfer_receiver
    }
    .ok_or(StepError::MissingSelectedAccount)?;
    let initial_balance = if sender {
        world.environment.sender_initial_balance
    } else {
        world.environment.receiver_initial_balance
    }
    .ok_or(StepError::MissingObservedBalance)?;
    let amount = world
        .environment
        .rejected_transfer_amount
        .ok_or(StepError::MissingObservedBalance)?;
    Ok((account, initial_balance, amount))
}

pub async fn get_transfer_transaction(
    client: &sequencer_service_rpc::SequencerClient,
    transfer_hash: common::HashType,
) -> Result<(LeeTransaction, u64), StepError> {
    client
        .get_transaction(transfer_hash)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("transfer {transfer_hash} was not found in the sequencer"),
        })
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
