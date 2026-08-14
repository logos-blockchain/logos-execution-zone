use std::time::Duration;

use cucumber::{gherkin::Step, then};
use indexer_service_rpc::RpcClient as IndexerRpcClient;
use sequencer_service_rpc::RpcClient as SequencerRpcClient;

use super::super::log_step;
use crate::{
    cucumber::{
        error::{StepError, StepResult},
        steps::transfers::helpers::transfer_artifact,
        world::CucumberWorld,
    },
    tf::{
        IndexerCatchUpError, wait_for_indexer_to_catch_up_with_timeout,
        wait_for_indexer_to_index_transactions_with_timeout,
    },
};

#[then(
    expr = "the transferred public account states for transfer {string} match between the sequencer and indexer"
)]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers receive mutable world references"
)]
async fn assert_transferred_public_account_states_match(
    world: &mut CucumberWorld,
    step: &Step,
    transfer_name: String,
) -> StepResult {
    log_step(step);
    let context = world.lez()?;
    let artifact = transfer_artifact(world, &transfer_name)?;
    let accounts = [artifact.sender, artifact.receiver];
    for account in accounts {
        let sequencer_state = SequencerRpcClient::get_account(context.sequencer_client(), account)
            .await
            .map_err(|error| StepError::QueryFailed {
                message: error.to_string(),
            })?;
        let indexer_state =
            IndexerRpcClient::get_account(&**context.indexer_client(), account.into())
                .await
                .map_err(|error| StepError::QueryFailed {
                    message: error.to_string(),
                })?;
        if indexer_state != sequencer_state.into() {
            return Err(StepError::AssertionFailed {
                message: format!(
                    "indexer and sequencer states differ for public account {account:?}"
                ),
            });
        }
    }
    Ok(())
}

#[then(expr = "the indexer catches up to transfer {string} within {int} seconds")]
async fn wait_for_named_transfer_indexer(
    world: &mut CucumberWorld,
    step: &Step,
    transfer_name: String,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let artifact = transfer_artifact(world, &transfer_name)?;
    let block_id = artifact
        .inclusion_block
        .ok_or_else(|| StepError::MissingTransferInclusion {
            name: transfer_name.clone(),
        })?;
    let context = world.lez()?;
    let result = wait_for_indexer_to_index_transactions_with_timeout(
        context.indexer(),
        &[artifact.hash],
        block_id,
        Duration::from_secs(timeout_seconds),
    )
    .await;
    let height = result.map_err(|error| match error {
        IndexerCatchUpError::Timeout {
            target,
            last_observed,
            elapsed,
        } => StepError::Timeout {
            message: format!(
                "indexer did not reach transfer '{transfer_name}' target block {target}; \
                 last observed indexer block {last_observed} after {elapsed:?}"
            ),
        },
        IndexerCatchUpError::SequencerQuery { message }
        | IndexerCatchUpError::IndexerQuery { message } => StepError::QueryFailed { message },
    })?;
    world.environment.observed_indexer_height = Some(height);
    Ok(())
}

#[then(expr = "the indexer catches up to the sequencer within {int} seconds")]
async fn wait_for_indexer(
    world: &mut CucumberWorld,
    step: &Step,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let timeout = Duration::from_secs(timeout_seconds);
    let context = world.lez()?;
    let result =
        wait_for_indexer_to_catch_up_with_timeout(context.indexer(), context.sequencer(), timeout)
            .await;
    let height = result.map_err(|error| match error {
        IndexerCatchUpError::Timeout {
            target,
            last_observed,
            elapsed,
        } => StepError::Timeout {
            message: format!(
                "indexer did not reach target block {target}; last observed indexer \
                 block {last_observed} after {elapsed:?}"
            ),
        },
        IndexerCatchUpError::SequencerQuery { message }
        | IndexerCatchUpError::IndexerQuery { message } => StepError::QueryFailed { message },
    })?;

    world.environment.observed_indexer_height = Some(height);
    Ok(())
}
