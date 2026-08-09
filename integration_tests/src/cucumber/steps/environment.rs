use common::transaction::LeeTransaction;
use cucumber::{given, then, when};
use lee::{AccountId, PublicKey};
use sequencer_service_rpc::RpcClient as _;

use crate::{
    config::{default_private_accounts_for_wallet, default_public_accounts_for_wallet},
    cucumber::{
        context::LezScenarioContext,
        error::{StepError, StepResult},
        world::CucumberWorld,
    },
    tf::{IndexerCatchUpError, LezLocalApp, wait_for_indexer_to_catch_up},
};

#[given("a LEZ smoke stack")]
async fn deploy_lez_smoke_stack(world: &mut CucumberWorld) -> StepResult {
    deploy_lez_stack(world, false).await
}

#[given("a LEZ private smoke stack")]
async fn deploy_lez_private_smoke_stack(world: &mut CucumberWorld) -> StepResult {
    deploy_lez_stack(world, true).await
}

#[given("a LEZ stack with configured accounts")]
async fn deploy_lez_configured_accounts(world: &mut CucumberWorld) -> StepResult {
    deploy_lez_stack(world, false).await
}

async fn deploy_lez_stack(
    world: &mut CucumberWorld,
    initialize_private_accounts: bool,
) -> StepResult {
    if world.lez.is_some() {
        return Err(StepError::FixtureAlreadyDeployed);
    }

    let entropy = world
        .test_context
        .clone()
        .unwrap_or_else(|| "unknown-time".to_owned());
    let scenario_base_dir = world.scenario_base_dir.join(entropy);
    let app = LezLocalApp::new().with_scenario_base_dir(scenario_base_dir);
    let app = if initialize_private_accounts {
        app
    } else {
        // The public smoke scenario deliberately exercises only the
        // public-account path. The private smoke scenario uses the default
        // fixture so private-account initialization is covered separately.
        app.without_private_account_initialization()
    };

    world
        .deployment_mut()
        .deploy(app)
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

#[when("I query the balance of the first configured private account")]
async fn query_first_private_account_balance(world: &mut CucumberWorld) -> StepResult {
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

    world.environment.selected_account = Some(account);
    world.environment.observed_balance = Some(observed_balance);
    world.environment.expected_balance = Some(expected_balance);
    Ok(())
}

#[when("I transfer 100 from the first configured public account to the second")]
async fn transfer_between_configured_public_accounts(world: &mut CucumberWorld) -> StepResult {
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
    let transfer_hash = context.public_transfer(sender, receiver, 100).await?;

    world.environment.transfer_sender = Some(sender);
    world.environment.transfer_receiver = Some(receiver);
    world.environment.transfer_amount = Some(100);
    world.environment.sender_initial_balance = Some(sender_initial_balance);
    world.environment.receiver_initial_balance = Some(receiver_initial_balance);
    world.environment.transfer_hash = Some(transfer_hash);
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

#[then("the sender balance decreases by 100")]
async fn assert_sender_balance_decreased(world: &mut CucumberWorld) -> StepResult {
    let (sender, initial_balance, amount) = transfer_details(world, true)?;
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

#[then("the receiver balance increases by 100")]
async fn assert_receiver_balance_increased(world: &mut CucumberWorld) -> StepResult {
    let (receiver, initial_balance, amount) = transfer_details(world, false)?;
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

#[then("the transfer is included in a block")]
async fn assert_transfer_is_included(world: &mut CucumberWorld) -> StepResult {
    let transfer_hash = world
        .environment
        .transfer_hash
        .ok_or(StepError::MissingTransfer)?;
    let (_, block_id) = get_transfer_transaction(world.lez()?, transfer_hash).await?;
    world.environment.transfer_included_block = Some(block_id);
    Ok(())
}

#[then("only the sender signs the transfer")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
async fn assert_only_sender_signs(world: &mut CucumberWorld) -> StepResult {
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

fn expected_public_signing_key(account: AccountId) -> Option<PublicKey> {
    default_public_accounts_for_wallet()
        .into_iter()
        .find_map(|(private_key, _)| {
            let public_key = PublicKey::new_from_private_key(&private_key);
            (AccountId::from(&public_key) == account).then_some(public_key)
        })
}

fn transfer_details(
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

async fn get_transfer_transaction(
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
