use std::time::Duration;

use cucumber::{gherkin::Step, then};
use indexer_service_rpc::RpcClient as IndexerRpcClient;
use sequencer_service_rpc::RpcClient as SequencerRpcClient;

use super::super::log_step;
use crate::{
    cucumber::{
        error::{StepError, StepResult},
        world::CucumberWorld,
    },
    tf::{
        IndexerCatchUpError, wait_for_indexer_to_catch_up_with_timeout,
        wait_for_indexer_to_index_transactions_with_timeout,
        wait_for_indexer_to_reach_with_timeout,
    },
};

#[then("the transferred public account states match between the sequencer and indexer")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers receive mutable world references"
)]
async fn assert_transferred_public_account_states_match(
    world: &mut CucumberWorld,
    step: &Step,
) -> StepResult {
    log_step(step);
    let context = world.lez()?;
    let accounts = [
        world
            .environment
            .transfer_sender
            .ok_or(StepError::MissingTransfer)?,
        world
            .environment
            .transfer_receiver
            .ok_or(StepError::MissingTransfer)?,
    ];
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

#[then(expr = "the indexer catches up to the sequencer within {int} seconds")]
async fn wait_for_indexer(
    world: &mut CucumberWorld,
    step: &Step,
    timeout_seconds: u64,
) -> StepResult {
    log_step(step);
    let timeout = Duration::from_secs(timeout_seconds);
    let transfer_block = world
        .environment
        .transfer_included_blocks
        .iter()
        .copied()
        .max()
        .or(world.environment.transfer_included_block);
    let context = world.lez()?;
    let result = match transfer_block {
        Some(block_id) if !world.environment.transfer_hashes.is_empty() => {
            wait_for_indexer_to_index_transactions_with_timeout(
                context.indexer(),
                &world.environment.transfer_hashes,
                block_id,
                timeout,
            )
            .await
        }
        Some(block_id) => {
            wait_for_indexer_to_reach_with_timeout(context.indexer(), block_id, timeout).await
        }
        None => {
            wait_for_indexer_to_catch_up_with_timeout(
                context.indexer(),
                context.sequencer(),
                timeout,
            )
            .await
        }
    };
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
