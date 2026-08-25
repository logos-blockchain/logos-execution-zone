use std::time::{Duration, Instant};

use cucumber::{gherkin::Step, then};
use indexer_service_rpc::RpcClient as IndexerRpcClient;
use sequencer_service_rpc::RpcClient as SequencerRpcClient;

use super::{
    super::{
        log_step,
        transfers::helpers::{transfer_artifact, wait_for_transfer_inclusion},
    },
    require_sequencer,
};
use crate::{
    cucumber::{
        error::{StepError, StepResult},
        steps::indexer::convergence::wait_for_named_transfer_indexed,
        world::CucumberWorld,
    },
    testing_framework::{IndexerCatchUpError, wait_for_indexer_to_reach_with_timeout},
};

const POLL_INTERVAL: Duration = Duration::from_secs(2);

async fn common_hash_state(
    first: &sequencer_service_rpc::SequencerClient,
    second: &sequencer_service_rpc::SequencerClient,
) -> Result<(u64, u64, Option<u64>), StepError> {
    let first_height = SequencerRpcClient::get_last_block_id(first)
        .await
        .map_err(StepError::query_failed)?;
    let second_height = SequencerRpcClient::get_last_block_id(second)
        .await
        .map_err(StepError::query_failed)?;
    for block_id in 1..=first_height.min(second_height) {
        let first_block = SequencerRpcClient::get_block(first, block_id)
            .await
            .map_err(StepError::query_failed)?;
        let second_block = SequencerRpcClient::get_block(second, block_id)
            .await
            .map_err(StepError::query_failed)?;
        if !matches!((&first_block, &second_block), (Some(a), Some(b)) if a.header.hash == b.header.hash)
        {
            return Ok((first_height, second_height, Some(block_id)));
        }
    }
    Ok((first_height, second_height, None))
}

#[then(
    expr = "transfer {string} is included in a block on sequencer {string} within {int} seconds"
)]
async fn assert_committee_transfer_is_included(
    world: &mut CucumberWorld,
    step: &Step,
    transfer_name: String,
    sequencer_alias: String,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let artifact = transfer_artifact(world, &transfer_name)?;
    let sequencer = require_sequencer(world.sequencer_registry()?.registry(), &sequencer_alias)?;
    let block_id = wait_for_transfer_inclusion(
        sequencer.client(),
        &artifact,
        Duration::from_secs(timeout_seconds),
        &format!("transfer '{transfer_name}' was not included on sequencer '{sequencer_alias}'"),
    )
    .await?;
    world
        .environment
        .transfers
        .artifacts
        .get_mut(&transfer_name)
        .ok_or_else(|| StepError::UnknownTransferArtifact {
            name: transfer_name.clone(),
        })?
        .inclusion_block = Some(block_id);
    Ok(())
}

#[then(
    expr = "sequencer {string} observes the receiver balance increase for transfer {string} by {int} within {int} seconds"
)]
async fn sequencer_observes_receiver_balance_increase(
    world: &mut CucumberWorld,
    step: &Step,
    observer_alias: String,
    transfer_name: String,
    amount: u128,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let artifact = transfer_artifact(world, &transfer_name)?;
    let context = world.sequencer_registry()?;
    let registry = context.registry();
    let observer = require_sequencer(registry, &observer_alias)?;
    if artifact.receiver_balance_observer.as_deref() != Some(&observer_alias) {
        return Err(StepError::AssertionFailed {
            message: format!(
                "receiver baseline was not recorded on observing sequencer '{observer_alias}'"
            ),
        });
    }
    let receiver = artifact.receiver;
    let initial_balance = artifact.receiver_balance_before;
    if artifact.amount != amount {
        return Err(StepError::AssertionFailed {
            message: format!(
                "transfer '{transfer_name}' has amount {}, expected {amount}",
                artifact.amount
            ),
        });
    }
    let expected_balance = initial_balance
        .checked_add(artifact.amount)
        .ok_or_else(|| StepError::AssertionFailed {
            message: format!("receiver balance overflow after adding {amount}"),
        })?;
    let timeout = Duration::from_secs(timeout_seconds);
    let wait = async {
        loop {
            let observed = observer
                .client()
                .get_account_balance(receiver, programs::authenticated_transfer().id())
                .await
                .map_err(StepError::query_failed)?;
            if observed == expected_balance {
                return Ok::<(), StepError>(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    };
    tokio::time::timeout(timeout, wait)
        .await
        .map_err(|_elapsed| StepError::Timeout {
            message: format!(
                "sequencer '{observer_alias}' did not observe receiver balance {expected_balance} within {timeout:?}"
            ),
        })??;
    world.environment.indexer.committee_target_height = Some(
        observer
            .client()
            .get_last_block_id()
            .await
            .map_err(StepError::query_failed)?,
    );
    Ok(())
}

#[then(
    expr = "sequencers {string} and {string} have identical common block hashes within {int} seconds"
)]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers receive mutable world references"
)]
async fn sequencers_have_identical_common_block_hashes(
    world: &mut CucumberWorld,
    step: &Step,
    first_alias: String,
    second_alias: String,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let registry = world.sequencer_registry()?.registry();
    let first = require_sequencer(registry, &first_alias)?;
    let second = require_sequencer(registry, &second_alias)?;
    let timeout = Duration::from_secs(timeout_seconds);
    let started = Instant::now();
    loop {
        let (first_height, second_height, first_divergent_block) =
            common_hash_state(first.client(), second.client()).await?;
        if first_divergent_block.is_none() {
            return Ok(());
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Err(StepError::Timeout {
                message: format!(
                    "sequencers '{first_alias}' and '{second_alias}' did not converge through block {} within {timeout:?}; heights were {first_height} and {second_height}",
                    first_divergent_block.unwrap_or_default()
                ),
            });
        }
        let remaining = timeout.saturating_sub(elapsed);
        tokio::time::sleep(POLL_INTERVAL.min(remaining)).await;
    }
}

#[then(
    expr = "the indexer finalizes transfer {string} on the committee chain within {int} seconds"
)]
async fn indexer_finalizes_committee_chain(
    world: &mut CucumberWorld,
    step: &Step,
    transfer_name: String,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let context = world.sequencer_registry()?;
    let artifact = transfer_artifact(world, &transfer_name)?;
    let timeout = Duration::from_secs(timeout_seconds);
    let mut height =
        wait_for_named_transfer_indexed(context.indexer(), &artifact, &transfer_name, timeout)
            .await?;
    if let Some(committee_target) = world.environment.indexer.committee_target_height
        && committee_target > height
    {
        height = wait_for_indexer_to_reach_with_timeout(
            context.indexer(),
            committee_target,
            timeout,
        )
            .await
            .map_err(|error| match error {
                IndexerCatchUpError::Timeout {
                    target,
                    last_observed,
                    elapsed,
                } => StepError::Timeout {
                    message: format!(
                        "indexer did not reach committee target block {target}; last observed {last_observed} after {elapsed:?}"
                    ),
                },
                IndexerCatchUpError::SequencerQuery { message }
                | IndexerCatchUpError::IndexerQuery { message } => StepError::QueryFailed { message },
            })?;
    }
    world.environment.indexer.committee_finalized_height = Some(height);
    Ok(())
}

#[then(expr = "finalized indexer blocks match sequencer {string}")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers receive mutable world references"
)]
async fn finalized_indexer_blocks_match_sequencer(
    world: &mut CucumberWorld,
    step: &Step,
    sequencer_alias: String,
) -> StepResult {
    log_step(step);
    let context = world.sequencer_registry()?;
    let sequencer = require_sequencer(context.registry(), &sequencer_alias)?;
    let finalized = world.environment.indexer.committee_finalized_height.ok_or(
        StepError::MissingObservation {
            field: "committee indexer finalized height",
        },
    )?;
    for block_id in 1..=finalized {
        let indexer_block =
            IndexerRpcClient::get_block_by_id(&**context.indexer_client(), block_id)
                .await
                .map_err(StepError::query_failed)?
                .ok_or_else(|| StepError::QueryFailed {
                    message: format!("indexer is missing finalized block {block_id}"),
                })?;
        let sequencer_block = SequencerRpcClient::get_block(sequencer.client(), block_id)
            .await
            .map_err(StepError::query_failed)?
            .ok_or_else(|| StepError::QueryFailed {
                message: format!("sequencer '{sequencer_alias}' is missing block {block_id}"),
            })?;
        if indexer_block.header.hash
            != indexer_service_protocol::HashType::from(sequencer_block.header.hash)
        {
            return Err(StepError::AssertionFailed {
                message: format!(
                    "indexer diverges from sequencer '{sequencer_alias}' at block {block_id}"
                ),
            });
        }
    }
    Ok(())
}

#[then("the indexer is not stalled")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers receive mutable world references"
)]
async fn indexer_is_not_stalled(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let context = world.sequencer_registry()?;
    let status = IndexerRpcClient::get_status(&**context.indexer_client())
        .await
        .map_err(StepError::query_failed)?;
    if let Some(reason) = status.stall_reason {
        return Err(StepError::AssertionFailed {
            message: format!("indexer is stalled: {reason:?}"),
        });
    }
    Ok(())
}
