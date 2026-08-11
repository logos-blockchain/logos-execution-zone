use std::time::Duration;

use cucumber::{gherkin::Step, then};

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
