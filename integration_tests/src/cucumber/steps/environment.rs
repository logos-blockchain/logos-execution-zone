use cucumber::{given, then, when};
use lee::{AccountId, PublicKey};
use sequencer_service_rpc::RpcClient as _;

use crate::{
    config::default_public_accounts_for_wallet,
    cucumber::{
        context::LezScenarioContext,
        error::{StepError, StepResult},
        world::CucumberWorld,
    },
    tf::{IndexerCatchUpError, LezLocalApp, wait_for_indexer_to_catch_up},
};

#[given("a default LEZ stack")]
async fn deploy_default_lez_stack(world: &mut CucumberWorld) -> StepResult {
    if world.lez.is_some() {
        return Err(StepError::FixtureAlreadyDeployed);
    }

    let entropy = world
        .test_context
        .clone()
        .unwrap_or_else(|| "unknown-time".to_owned());
    let scenario_base_dir = world.scenario_base_dir.join(entropy);
    world
        .deployment_mut()
        .deploy(
            LezLocalApp::new()
                .with_scenario_base_dir(scenario_base_dir)
                // This smoke scenario deliberately exercises the public-account path. The
                // default TF deployment still initializes both public and private accounts;
                // the normal TF deployment test covers that complete fixture.
                .without_private_account_initialization(),
        )
        .await
        .map_err(|error| StepError::DeploymentFailed {
            message: format!("{error:?}"),
        })?;

    let context = LezScenarioContext::from_deployment(world.deployment())?;
    world.set_lez(context)
}

#[when("I query the balance of the first configured public account")]
async fn query_first_public_account_balance(world: &mut CucumberWorld) -> StepResult {
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

    world.environment.selected_account = Some(account);
    world.environment.observed_balance = Some(observed_balance);
    world.environment.expected_balance = Some(expected_balance);
    Ok(())
}

#[then("its balance matches the configured initial balance")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
fn assert_first_public_account_balance(world: &mut CucumberWorld) -> StepResult {
    let account = world
        .environment
        .selected_account
        .ok_or(StepError::MissingSelectedAccount)?;
    let observed_balance = world
        .environment
        .observed_balance
        .ok_or(StepError::MissingObservedBalance)?;
    let expected_balance =
        world
            .environment
            .expected_balance
            .ok_or_else(|| StepError::AssertionFailed {
                message: "expected balance was not recorded".to_owned(),
            })?;

    if observed_balance != expected_balance {
        return Err(StepError::AssertionFailed {
            message: format!(
                "account {account:?} has balance {observed_balance}, expected {expected_balance}"
            ),
        });
    }

    Ok(())
}

#[then("the indexer catches up to the sequencer")]
async fn wait_for_indexer(world: &mut CucumberWorld) -> StepResult {
    let context = world.lez()?;
    let height = wait_for_indexer_to_catch_up(context.indexer(), context.sequencer())
        .await
        .map_err(|error| match error {
            IndexerCatchUpError::Timeout {
                target,
                last_observed,
                elapsed,
            } => StepError::Timeout {
                message: format!(
                    "indexer did not catch up to sequencer block {target}; last observed indexer \
                     block {last_observed} after {elapsed:?}"
                ),
            },
            IndexerCatchUpError::SequencerQuery { message }
            | IndexerCatchUpError::IndexerQuery { message } => StepError::QueryFailed { message },
        })?;

    world.environment.observed_indexer_height = Some(height);
    Ok(())
}

#[then("I stop the runtime")]
async fn stop_runtime(world: &mut CucumberWorld) -> StepResult {
    world.stop_runtime().await
}

fn expected_public_balance(account: AccountId) -> Option<u128> {
    default_public_accounts_for_wallet()
        .into_iter()
        .find_map(|(private_key, balance)| {
            let configured_account =
                AccountId::from(&PublicKey::new_from_private_key(&private_key));
            (configured_account == account).then_some(balance)
        })
}
