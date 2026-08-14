use std::time::Duration;

use cucumber::{gherkin::Step, given, when};
use logos_blockchain_key_management_system_service::keys::Ed25519Key;
use sequencer_core::{block_publisher::post_channel_config, config::BedrockConfig};
use sequencer_service_rpc::RpcClient as _;
use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};

use super::{
    super::{
        log_step,
        transfers::helpers::{ensure_transfer_name_available, insert_transfer_artifact},
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
    let timeout = Duration::from_secs(timeout_seconds);
    let wait = async {
        loop {
            if client
                .get_last_block_id()
                .await
                .map_err(|error| StepError::QueryFailed {
                    message: error.to_string(),
                })?
                >= target
            {
                return Ok::<(), StepError>(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    };
    tokio::time::timeout(timeout, wait)
        .await
        .map_err(|_elapsed| StepError::Timeout {
            message: format!(
                "timed out waiting for {description} at block {target} within {timeout:?}"
            ),
        })??;
    Ok(())
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
        .map_err(|error| StepError::DeploymentFailed {
            message: format!(
                "step '{}' failed to start sequencer '{alias}': {error}",
                step.value
            ),
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

#[when(expr = "sequencer {string} configures the committee")]
async fn configure_committee(
    world: &mut CucumberWorld,
    step: &Step,
    leader_alias: String,
) -> StepResult {
    log_step(step);
    let configuration = parse_committee_config(step)?;
    let context = world.sequencer_registry()?;
    let registry = context.registry();
    let leader_key =
        registry
            .signing_key(&leader_alias)
            .ok_or_else(|| StepError::InvalidArgument {
                message: format!("sequencer '{leader_alias}' is not registered"),
            })?;
    let authorized_keys = configuration
        .authorized_sequencers
        .iter()
        .map(|alias| {
            registry
                .signing_key(alias)
                .map(|key| Ed25519Key::from_bytes(&key).public_key())
                .ok_or_else(|| StepError::InvalidArgument {
                    message: format!("authorized sequencer '{alias}' is not registered"),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let leader = require_sequencer(registry, &leader_alias)?;
    let bedrock_addr = context.bedrock().primary_api_addr();
    post_channel_config(
        &BedrockConfig {
            channel_id: config::bedrock_channel_id(),
            node_url: config::addr_to_url(UrlProtocol::Http, bedrock_addr).map_err(|error| {
                StepError::QueryFailed {
                    message: error.to_string(),
                }
            })?,
            funding_key: config::bedrock_funding_key(),
            auth: None,
            priority_fee: 10_000,
        },
        &Ed25519Key::from_bytes(&leader_key),
        authorized_keys,
        configuration.posting_timeframe,
        configuration.posting_timeout,
        configuration.withdraw_threshold,
        configuration.deposit_threshold,
    )
    .await
    .map_err(|error| StepError::QueryFailed {
        message: format!("failed to configure the committee: {error:#}"),
    })?;
    world.environment.committee_height_at_config =
        Some(leader.client().get_last_block_id().await.map_err(|error| {
            StepError::QueryFailed {
                message: error.to_string(),
            }
        })?);
    Ok(())
}

#[when(
    expr = "sequencer {string} advances after the committee reconfiguration within {int} seconds"
)]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers use the framework's mutable-world signature"
)]
async fn sequencer_advances_after_reconfiguration(
    world: &mut CucumberWorld,
    step: &Step,
    alias: String,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let configured_height =
        world
            .environment
            .committee_height_at_config
            .ok_or(StepError::MissingObservation {
                field: "committee reconfiguration height",
            })?;
    let sequencer = require_sequencer(world.sequencer_registry()?.registry(), &alias)?;
    let target = configured_height
        .checked_add(1)
        .ok_or_else(|| StepError::AssertionFailed {
            message: "committee reconfiguration height overflowed".to_owned(),
        })?;
    wait_for_height(
        sequencer.client(),
        target,
        timeout_seconds,
        &format!("sequencer '{alias}' after committee reconfiguration"),
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
    let join_height =
        source
            .client()
            .get_last_block_id()
            .await
            .map_err(|error| StepError::QueryFailed {
                message: error.to_string(),
            })?;
    let joining = require_sequencer(registry, &joining_alias)?;
    wait_for_height(
        joining.client(),
        join_height,
        timeout_seconds,
        &format!("sequencer '{joining_alias}' to synchronize to '{source_alias}'"),
    )
    .await?;
    world.environment.committee_join_height = Some(join_height);
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
    world.environment.committee_rotation_target = Some(target);
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
    if world.environment.committee_receiver != Some(receiver) {
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
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?
        .into_iter()
        .next()
        .ok_or_else(|| StepError::QueryFailed {
            message: format!("no nonce returned for deterministic sender {sender:?}"),
        })?;
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
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    world.environment.committee_receiver = Some(receiver);
    insert_transfer_artifact(
        world,
        transfer_name,
        TransferArtifact {
            hash: transaction_hash,
            sender,
            receiver,
            amount,
            kind: TransferKind::Public,
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
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    world.environment.committee_receiver = Some(account);
    world.environment.committee_receiver_balance_before = Some(balance);
    world.environment.committee_balance_observer = Some(observer_alias);
    Ok(())
}
