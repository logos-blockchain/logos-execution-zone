use common::transaction::LeeTransaction;
use lee::{AccountId, PublicKey};
use sequencer_service_rpc::RpcClient as _;

use crate::{
    config::default_public_accounts_for_wallet,
    cucumber::{
        context::LezScenarioContext,
        error::{StepError, StepResult},
        world::CucumberWorld,
    },
};

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
    sender: bool,
) -> Result<(AccountId, u128, u128), StepError> {
    let account = if sender {
        world.environment.transfer_sender
    } else {
        world.environment.transfer_receiver
    }
    .ok_or(StepError::MissingTransfer)?;
    let initial_balance = if sender {
        world.environment.sender_initial_balance
    } else {
        world.environment.receiver_initial_balance
    }
    .ok_or(StepError::MissingTransfer)?;
    let amount = world
        .environment
        .transfer_amount
        .ok_or(StepError::MissingTransfer)?;
    Ok((account, initial_balance, amount))
}

pub(crate) async fn get_transfer_transaction(
    context: &LezScenarioContext,
    transfer_hash: common::HashType,
) -> Result<(LeeTransaction, u64), StepError> {
    context
        .sequencer_client()
        .get_transaction(transfer_hash)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("transfer {transfer_hash} was not found in the sequencer"),
        })
}

pub(crate) async fn assert_private_commitment_in_state(
    world: &CucumberWorld,
    sender: bool,
    role: &str,
) -> StepResult {
    let account = if sender {
        world.environment.private_transfer_sender
    } else {
        world.environment.private_transfer_receiver
    }
    .ok_or(StepError::MissingTransfer)?;
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
