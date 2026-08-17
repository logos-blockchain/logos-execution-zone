use cucumber::{gherkin::Step, when};
use sequencer_service_rpc::RpcClient as _;

use super::super::log_step;
use crate::{
    config::default_private_accounts_for_wallet,
    cucumber::{
        error::{StepError, StepResult},
        steps::accounts::helpers::expected_public_balance,
        world::CucumberWorld,
    },
};

#[when("I query the balance of the first configured public account")]
async fn query_first_public_account_balance(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let context = world.lez()?;
    let account = context
        .existing_public_accounts()
        .await?
        .into_iter()
        .next()
        .ok_or(StepError::MissingSelectedAccount)?;

    let observed_balance = context
        .sequencer_client()
        .get_account_balance(account)
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;

    let expected_balance =
        expected_public_balance(account).ok_or_else(|| StepError::QueryFailed {
            message: format!("account {account:?} is not in the configured public accounts"),
        })?;

    world.environment.accounts.selected_account = Some(account);
    world.environment.accounts.observed_balance = Some(observed_balance);
    world.environment.accounts.expected_balance = Some(expected_balance);
    Ok(())
}

#[when("I query the balance of the first configured private account")]
async fn query_first_private_account_balance(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let context = world.lez()?;
    let account = context
        .existing_private_accounts()
        .await?
        .into_iter()
        .next()
        .ok_or(StepError::MissingSelectedAccount)?;

    let observed_balance = context
        .private_account_balance(account)
        .await?
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("private account {account:?} has no synchronized balance"),
        })?;

    let expected_balance = default_private_accounts_for_wallet()
        .into_iter()
        .find(|configured| configured.account_id() == account)
        .map(|configured| configured.balance)
        .ok_or_else(|| StepError::QueryFailed {
            message: format!(
                "private account {account:?} is not in the configured private accounts"
            ),
        })?;

    world.environment.accounts.selected_account = Some(account);
    world.environment.accounts.observed_balance = Some(observed_balance);
    world.environment.accounts.expected_balance = Some(expected_balance);
    Ok(())
}
