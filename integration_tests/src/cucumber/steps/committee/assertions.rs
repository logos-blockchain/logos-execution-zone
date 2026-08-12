use std::time::Duration;

use cucumber::{gherkin::Step, then};
use indexer_service_rpc::RpcClient as IndexerRpcClient;
use sequencer_service_rpc::RpcClient as SequencerRpcClient;

use super::{super::log_step, require_sequencer};
use crate::{
    cucumber::{
        error::{StepError, StepResult},
        world::CucumberWorld,
    },
    tf::{IndexerCatchUpError, wait_for_indexer_to_reach_with_timeout},
};

const POLL_INTERVAL: Duration = Duration::from_secs(2);

#[then(
    expr = "sequencer {string} observes the receiver balance increase by {int} within {int} seconds"
)]
async fn sequencer_observes_receiver_balance_increase(
    world: &mut CucumberWorld,
    step: &Step,
    observer_alias: String,
    amount: u128,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let context = world.sequencer_registry()?;
    let registry = context.registry();
    let observer = require_sequencer(registry, &observer_alias)?;
    let receiver = world
        .environment
        .committee_receiver
        .ok_or(StepError::MissingTransfer)?;
    let initial_balance = world
        .environment
        .committee_receiver_balance_before
        .ok_or(StepError::MissingTransfer)?;
    let expected_balance =
        initial_balance
            .checked_add(amount)
            .ok_or_else(|| StepError::AssertionFailed {
                message: format!("receiver balance overflow after adding {amount}"),
            })?;
    let timeout = Duration::from_secs(timeout_seconds);
    let wait = async {
        loop {
            let observed = observer
                .client()
                .get_account_balance(receiver)
                .await
                .map_err(|error| StepError::QueryFailed {
                    message: error.to_string(),
                })?;
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
    world.environment.committee_indexer_finalized_height = Some(
        observer
            .client()
            .get_last_block_id()
            .await
            .map_err(|error| StepError::QueryFailed {
                message: error.to_string(),
            })?,
    );
    Ok(())
}

#[then(expr = "sequencers {string} and {string} have identical common block hashes")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers receive mutable world references"
)]
async fn sequencers_have_identical_common_block_hashes(
    world: &mut CucumberWorld,
    step: &Step,
    first_alias: String,
    second_alias: String,
) -> StepResult {
    log_step(step);
    let registry = world.sequencer_registry()?.registry();
    let first = require_sequencer(registry, &first_alias)?;
    let second = require_sequencer(registry, &second_alias)?;
    let first_height = SequencerRpcClient::get_last_block_id(first.client())
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    let second_height = SequencerRpcClient::get_last_block_id(second.client())
        .await
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    for block_id in 1..=first_height.min(second_height) {
        let first_block = SequencerRpcClient::get_block(first.client(), block_id)
            .await
            .map_err(|error| StepError::QueryFailed {
                message: error.to_string(),
            })?
            .ok_or_else(|| StepError::QueryFailed {
                message: format!("sequencer '{first_alias}' is missing block {block_id}"),
            })?;
        let second_block = SequencerRpcClient::get_block(second.client(), block_id)
            .await
            .map_err(|error| StepError::QueryFailed {
                message: error.to_string(),
            })?
            .ok_or_else(|| StepError::QueryFailed {
                message: format!("sequencer '{second_alias}' is missing block {block_id}"),
            })?;
        if first_block.header.hash != second_block.header.hash {
            return Err(StepError::AssertionFailed {
                message: format!(
                    "sequencers '{first_alias}' and '{second_alias}' diverge at block {block_id}"
                ),
            });
        }
    }
    Ok(())
}

#[then(expr = "the indexer finalizes the committee chain within {int} seconds")]
async fn indexer_finalizes_committee_chain(
    world: &mut CucumberWorld,
    step: &Step,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let context = world.sequencer_registry()?;
    let target = world
        .environment
        .committee_indexer_finalized_height
        .ok_or(StepError::MissingTransfer)?;
    let result = wait_for_indexer_to_reach_with_timeout(
        context.indexer(),
        target,
        Duration::from_secs(timeout_seconds),
    )
    .await;
    let height = result.map_err(|error| match error {
        IndexerCatchUpError::Timeout {
            target: timeout_target,
            last_observed,
            elapsed,
        } => StepError::Timeout {
            message: format!(
                "indexer did not reach committee block {timeout_target}; last observed {last_observed} after {elapsed:?}"
            ),
        },
        IndexerCatchUpError::SequencerQuery { message }
        | IndexerCatchUpError::IndexerQuery { message } => StepError::QueryFailed { message },
    })?;
    world.environment.committee_indexer_finalized_height = Some(height);
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
    let finalized = world
        .environment
        .committee_indexer_finalized_height
        .ok_or(StepError::MissingTransfer)?;
    for block_id in 1..=finalized {
        let indexer_block =
            IndexerRpcClient::get_block_by_id(&**context.indexer_client(), block_id)
                .await
                .map_err(|error| StepError::QueryFailed {
                    message: error.to_string(),
                })?
                .ok_or_else(|| StepError::QueryFailed {
                    message: format!("indexer is missing finalized block {block_id}"),
                })?;
        let sequencer_block = SequencerRpcClient::get_block(sequencer.client(), block_id)
            .await
            .map_err(|error| StepError::QueryFailed {
                message: error.to_string(),
            })?
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
        .map_err(|error| StepError::QueryFailed {
            message: error.to_string(),
        })?;
    if let Some(reason) = status.stall_reason {
        return Err(StepError::AssertionFailed {
            message: format!("indexer is stalled: {reason:?}"),
        });
    }
    Ok(())
}
