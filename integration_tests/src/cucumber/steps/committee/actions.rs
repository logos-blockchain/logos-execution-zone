use std::time::Duration;

use cucumber::{gherkin::Step, given, when};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use sequencer_core::{
    block_publisher::{Ed25519PublicKey, read_channel_state},
    config::BedrockConfig,
};
use sequencer_service_rpc::RpcClient as _;
use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};

use super::{
    super::{
        log_step,
        transfers::helpers::{ensure_transfer_name_available, insert_transfer_artifact},
        wait_until,
    },
    parse_committee_config, parse_sequencer_registrations, require_sequencer,
};
use crate::{
    config::{self, UrlProtocol},
    cucumber::{
        error::{StepError, StepResult},
        world::{CucumberWorld, TransferArtifact, TransferKind},
    },
};

const POLL_INTERVAL: Duration = Duration::from_secs(2);

async fn wait_for_height(
    client: &sequencer_service_rpc::SequencerClient,
    target: u64,
    timeout_seconds: u64,
    description: &str,
) -> StepResult {
    wait_until(
        POLL_INTERVAL,
        Duration::from_secs(timeout_seconds),
        format!("{description} at block {target}"),
        || async move {
            Ok((client
                .get_last_block_id()
                .await
                .map_err(StepError::query_failed)?
                >= target)
                .then_some(()))
        },
    )
    .await
}

#[given("the following LEZ sequencers are registered")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    clippy::unused_async,
    reason = "Cucumber step handlers use the framework's async mutable-world signature"
)]
async fn register_lez_sequencers(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let registrations = parse_sequencer_registrations(step)?;
    let registry = world.sequencer_registry()?.registry();
    for (alias, signing_key) in registrations {
        registry
            .register(alias, signing_key)
            .map_err(|error| StepError::InvalidArgument {
                message: format!(
                    "step '{}' could not register sequencer: {error}",
                    step.value
                ),
            })?;
    }
    Ok(())
}

#[given(expr = "sequencer {string} configures the committee")]
#[expect(
    clippy::unused_async,
    reason = "Cucumber step handlers use the framework's mutable-world signature"
)]
async fn configure_committee(
    world: &mut CucumberWorld,
    step: &Step,
    leader_alias: String,
) -> StepResult {
    log_step(step);
    let authorized_sequencers = parse_committee_config(step, &leader_alias)?;
    let registry = world.sequencer_registry()?.registry();
    if registry.signing_key(&leader_alias).is_none() {
        return Err(StepError::InvalidArgument {
            message: format!("committee leader '{leader_alias}' is not registered"),
        });
    }
    for alias in &authorized_sequencers {
        if registry.signing_key(alias).is_none() {
            return Err(StepError::InvalidArgument {
                message: format!("authorized sequencer '{alias}' is not registered"),
            });
        }
    }
    registry
        .configure_initial_committee(&authorized_sequencers)
        .map_err(|error| StepError::InvalidArgument {
            message: format!(
                "step '{}' could not configure the committee: {error}",
                step.value
            ),
        })?;
    world.environment.committee.committee_configuration =
        Some(crate::cucumber::world::CommitteeConfiguration {
            leader_alias,
            authorized_sequencers,
        });
    Ok(())
}

#[when(expr = "I start sequencer {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers use the framework's mutable-world signature"
)]
async fn start_sequencer(world: &mut CucumberWorld, step: &Step, alias: String) -> StepResult {
    log_step(step);
    world
        .sequencer_registry()?
        .registry()
        .start(&alias)
        .await
        .map_err(|error| {
            StepError::deployment_failed_boxed(
                error,
                format!("step '{}' failed to start sequencer '{alias}'", step.value),
            )
        })
}

#[when(expr = "sequencer {string} reaches block {int} within {int} seconds")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers use the framework's mutable-world signature"
)]
async fn sequencer_reaches_block(
    world: &mut CucumberWorld,
    step: &Step,
    alias: String,
    target: u64,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let sequencer = require_sequencer(world.sequencer_registry()?.registry(), &alias)?;
    wait_for_height(
        sequencer.client(),
        target,
        timeout_seconds,
        &format!("sequencer '{alias}' to reach block {target}"),
    )
    .await
}

#[when(expr = "sequencer {string} synchronizes to sequencer {string} within {int} seconds")]
async fn sequencer_synchronizes(
    world: &mut CucumberWorld,
    step: &Step,
    joining_alias: String,
    source_alias: String,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let registry = world.sequencer_registry()?.registry();
    let source = require_sequencer(registry, &source_alias)?;
    let join_height = source
        .client()
        .get_last_block_id()
        .await
        .map_err(StepError::query_failed)?;
    let joining = require_sequencer(registry, &joining_alias)?;
    wait_for_height(
        joining.client(),
        join_height,
        timeout_seconds,
        &format!("sequencer '{joining_alias}' to synchronize to '{source_alias}'"),
    )
    .await?;
    world.environment.committee.committee_join_height = Some(join_height);
    Ok(())
}

#[when(expr = "the committee configured by sequencer {string} is active within {int} seconds")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers receive the framework's mutable-world signature"
)]
async fn committee_is_active(
    world: &mut CucumberWorld,
    step: &Step,
    leader_alias: String,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let configuration = world
        .environment
        .committee
        .committee_configuration
        .as_ref()
        .ok_or(StepError::MissingObservation {
            field: "committee configuration",
        })?;
    if configuration.leader_alias != leader_alias {
        return Err(StepError::AssertionFailed {
            message: format!(
                "committee was configured by '{}', not '{leader_alias}'",
                configuration.leader_alias
            ),
        });
    }
    let context = world.sequencer_registry()?;
    require_sequencer(context.registry(), &leader_alias)?;
    let expected_keys = configuration
        .authorized_sequencers
        .iter()
        .map(|alias| {
            let signing_key = context.registry().signing_key(alias).ok_or_else(|| {
                StepError::InvalidArgument {
                    message: format!("authorized sequencer '{alias}' is not registered"),
                }
            })?;
            Ok(Ed25519Key::from_bytes(&signing_key).public_key().to_bytes())
        })
        .collect::<Result<Vec<_>, StepError>>()?;
    let bedrock_config = BedrockConfig {
        channel_id: config::bedrock_channel_id(),
        node_url: config::addr_to_url(UrlProtocol::Http, context.bedrock().primary_api_addr())
            .map_err(|source| StepError::QueryFailedSource { source })?,
        funding_key: config::bedrock_funding_key(),
        auth: None,
        priority_fee: 10_000,
    };
    let timeout = Duration::from_secs(timeout_seconds);
    let wait = async {
        loop {
            let state = read_channel_state(&bedrock_config)
                .await
                .map_err(|source| StepError::QueryFailedSource { source })?;
            let active = state.is_some_and(|state| {
                let mut actual_keys = state
                    .accredited_keys
                    .iter()
                    .map(Ed25519PublicKey::to_bytes)
                    .collect::<Vec<_>>();
                actual_keys.sort_unstable();
                let mut expected_keys = expected_keys.clone();
                expected_keys.sort_unstable();
                actual_keys == expected_keys
            });
            if active {
                return Ok::<(), StepError>(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    };
    tokio::time::timeout(timeout, wait)
        .await
        .map_err(|_elapsed| StepError::Timeout {
            message: format!(
                "committee configured by '{leader_alias}' was not active within {timeout:?}"
            ),
        })??;
    Ok(())
}

#[when(expr = "sequencer {string} becomes the posting turn within {int} seconds")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers receive the framework's mutable-world signature"
)]
async fn sequencer_becomes_posting_turn(
    world: &mut CucumberWorld,
    step: &Step,
    alias: String,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let context = world.sequencer_registry()?;
    let signing_key =
        context
            .registry()
            .signing_key(&alias)
            .ok_or_else(|| StepError::InvalidArgument {
                message: format!("sequencer '{alias}' is not registered"),
            })?;
    let expected_key: Ed25519PublicKey = Ed25519Key::from_bytes(&signing_key).public_key();
    let bedrock_config = BedrockConfig {
        channel_id: config::bedrock_channel_id(),
        node_url: config::addr_to_url(UrlProtocol::Http, context.bedrock().primary_api_addr())
            .map_err(|source| StepError::QueryFailedSource { source })?,
        funding_key: config::bedrock_funding_key(),
        auth: None,
        priority_fee: 10_000,
    };
    let timeout = Duration::from_secs(timeout_seconds);
    let wait = async {
        loop {
            let is_turn = read_channel_state(&bedrock_config)
                .await
                .map_err(|source| StepError::QueryFailedSource { source })?
                .and_then(|state| {
                    state
                        .accredited_keys
                        .get(usize::from(state.tip_sequencer))
                        .copied()
                })
                == Some(expected_key);
            if is_turn {
                return Ok::<(), StepError>(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    };
    tokio::time::timeout(timeout, wait)
        .await
        .map_err(|_elapsed| StepError::Timeout {
            message: format!(
                "sequencer '{alias}' did not become the posting turn within {timeout:?}"
            ),
        })??;
    Ok(())
}

#[when(
    expr = "sequencers {string} and {string} advance across {int} rotation blocks within {int} seconds"
)]
async fn sequencers_advance_across_rotation_blocks(
    world: &mut CucumberWorld,
    step: &Step,
    first_alias: String,
    second_alias: String,
    rotation_blocks: u64,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let join_height =
        world
            .environment
            .committee
            .committee_join_height
            .ok_or(StepError::MissingObservation {
                field: "committee join height",
            })?;
    let target =
        join_height
            .checked_add(rotation_blocks)
            .ok_or_else(|| StepError::AssertionFailed {
                message: "committee rotation target overflowed".to_owned(),
            })?;
    let registry = world.sequencer_registry()?.registry();
    let first = require_sequencer(registry, &first_alias)?;
    let second = require_sequencer(registry, &second_alias)?;
    wait_for_height(
        first.client(),
        target,
        timeout_seconds,
        &format!("sequencer '{first_alias}' across committee rotation windows"),
    )
    .await?;
    wait_for_height(
        second.client(),
        target,
        timeout_seconds,
        &format!("sequencer '{second_alias}' across committee rotation windows"),
    )
    .await?;
    world.environment.committee.committee_rotation_target = Some(target);
    Ok(())
}

#[when(
    expr = "I submit {int} from deterministic public account {int} to account {int} through sequencer {string} as {string}"
)]
async fn submit_committee_transfer(
    world: &mut CucumberWorld,
    step: &Step,
    amount: u128,
    sender_index: usize,
    receiver_index: usize,
    sequencer_alias: String,
    transfer_name: String,
) -> StepResult {
    log_step(step);
    ensure_transfer_name_available(world, &transfer_name)?;
    let registry = world.sequencer_registry()?.registry();
    let sequencer = require_sequencer(registry, &sequencer_alias)?;
    let accounts = initial_public_user_accounts();
    let sender = accounts
        .get(sender_index)
        .ok_or_else(|| StepError::InvalidArgument {
            message: format!("sender account index {sender_index} is out of range"),
        })?
        .account_id;
    let receiver = accounts
        .get(receiver_index)
        .ok_or_else(|| StepError::InvalidArgument {
            message: format!("receiver account index {receiver_index} is out of range"),
        })?
        .account_id;
    let pending_observation = world
        .environment
        .transfers
        .pending_observation
        .as_ref()
        .ok_or(StepError::MissingObservation {
            field: "committee transfer receiver baseline",
        })?;
    if pending_observation.receiver != receiver {
        return Err(StepError::AssertionFailed {
            message: format!(
                "transfer receiver {receiver:?} does not match the recorded observer baseline"
            ),
        });
    }
    let nonce = sequencer
        .client()
        .get_accounts_nonces(vec![sender])
        .await
        .map_err(StepError::query_failed)?
        .into_iter()
        .next()
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("no nonce returned for deterministic sender {sender:?}"),
        })?;
    let sender_balance_before = sequencer
        .client()
        .get_account_balance(sender)
        .await
        .map_err(StepError::query_failed)?;
    let signing_key = initial_pub_accounts_private_keys()
        .get(sender_index)
        .ok_or_else(|| StepError::InvalidArgument {
            message: format!("sender account index {sender_index} has no signing key"),
        })?
        .pub_sign_key
        .clone();
    let transaction = common::test_utils::create_transaction_native_token_transfer(
        sender,
        nonce.0,
        receiver,
        amount,
        &signing_key,
    );
    let transaction_hash = sequencer
        .client()
        .send_transaction(transaction)
        .await
        .map_err(StepError::query_failed)?;
    let submitted_observation = world
        .environment
        .transfers
        .pending_observation
        .take()
        .ok_or(StepError::MissingObservation {
            field: "committee transfer receiver baseline",
        })?;
    insert_transfer_artifact(
        world,
        transfer_name,
        TransferArtifact {
            hash: transaction_hash,
            sender,
            receiver,
            amount,
            kind: TransferKind::Public,
            sender_balance_before,
            receiver_balance_before: submitted_observation.receiver_balance_before,
            sender_nonce_before: Some(nonce),
            receiver_balance_observer: Some(submitted_observation.observer_alias),
            inclusion_block: None,
        },
    )?;
    Ok(())
}

#[when(expr = "I record deterministic public account {int} balance on sequencer {string}")]
async fn record_committee_balance_baseline(
    world: &mut CucumberWorld,
    step: &Step,
    account_index: usize,
    observer_alias: String,
) -> StepResult {
    log_step(step);
    let account = initial_public_user_accounts()
        .get(account_index)
        .ok_or_else(|| StepError::InvalidArgument {
            message: format!("account index {account_index} is out of range"),
        })?
        .account_id;
    let observer = require_sequencer(world.sequencer_registry()?.registry(), &observer_alias)?;
    let balance = observer
        .client()
        .get_account_balance(account)
        .await
        .map_err(StepError::query_failed)?;
    world.environment.transfers.pending_observation =
        Some(crate::cucumber::world::PendingTransferObservation {
            receiver: account,
            receiver_balance_before: balance,
            observer_alias,
        });
    Ok(())
}
