//! Chain access shared by the stake lifecycle steps: account and config
//! queries, submission bookkeeping and the inclusion/non-inclusion waits.

use std::time::Duration;

use common::HashType;
use lee::{Account, AccountId};
use lee_core::program::{InstructionData, ProgramId};
use sequencer_service_rpc::RpcClient as _;
use sequencer_stake_core::{SequencerEntry, SequencerKey, SequencerStakeConfig};
use wallet::AccountIdentity;

use crate::cucumber::{
    context::LezScenarioContext,
    error::{StepError, StepResult},
    stake_scenario::{AccountsSnapshot, SubmissionRecord, stake_instruction},
    world::CucumberWorld,
};

/// Cadence of the inclusion and non-inclusion polls.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Upper bound on every wait; generous because a freshly accredited key with
/// no node behind it slows block production down to the posting-turn reclaim.
const WAIT_TIMEOUT: Duration = Duration::from_secs(120);

/// Blocks past the submission tip that prove a dropped transaction: the
/// builder pulls the whole mempool on every turn, so once two more blocks
/// exist the transaction was tried and dropped rather than still queued.
const NON_INCLUSION_BLOCKS: u64 = 2;

/// Reads one account from the sequencer; an untouched account comes back with
/// default values.
pub(super) async fn get_account(
    context: &LezScenarioContext,
    account_id: AccountId,
) -> Result<Account, StepError> {
    context
        .sequencer_client()
        .get_account(account_id)
        .await
        .map_err(StepError::query_failed)
}

/// Reads and decodes the `sequencer_stake` config account.
pub(super) async fn stake_config(
    context: &LezScenarioContext,
) -> Result<SequencerStakeConfig, StepError> {
    let account = get_account(context, system_accounts::sequencer_stake_config_account_id()).await?;
    SequencerStakeConfig::from_bytes(account.data.as_ref()).ok_or_else(|| {
        StepError::LogicalError {
            message: "the config account does not decode as a SequencerStakeConfig".to_owned(),
        }
    })
}

/// Returns the config entry backing `sequencer_key`, if any.
pub(super) async fn config_entry(
    context: &LezScenarioContext,
    sequencer_key: SequencerKey,
) -> Result<Option<SequencerEntry>, StepError> {
    Ok(stake_config(context).await?.entries.get(&sequencer_key).copied())
}

/// Returns the first public account configured into the scenario wallet.
pub(super) async fn first_configured_public_account(
    context: &LezScenarioContext,
) -> Result<AccountId, StepError> {
    context
        .existing_public_accounts()
        .await?
        .into_iter()
        .next()
        .ok_or(StepError::MissingSelectedAccount)
}

/// Returns the sequencer's current tip.
pub(super) async fn last_block(context: &LezScenarioContext) -> Result<u64, StepError> {
    context
        .sequencer_client()
        .get_last_block_id()
        .await
        .map_err(StepError::query_failed)
}

/// Snapshots the config account plus every scenario account introduced so
/// far, immediately before a submission.
pub(super) async fn scenario_snapshot(
    world: &CucumberWorld,
) -> Result<AccountsSnapshot, StepError> {
    let scenario = world.stake()?;
    let context = world.lez()?;
    let mut account_ids = vec![system_accounts::sequencer_stake_config_account_id()];
    account_ids.extend(scenario.funding_id().ok());
    account_ids.extend(scenario.ownership_id().ok());
    account_ids.extend(scenario.second_ownership_id().ok());

    let mut accounts = Vec::with_capacity(account_ids.len());
    for account_id in account_ids {
        accounts.push((account_id, get_account(context, account_id).await?));
    }
    Ok(AccountsSnapshot::new(accounts))
}

/// Snapshots the touchable accounts, submits one transaction through the
/// scenario wallet and records it for the inclusion/non-inclusion assertions.
pub(super) async fn submit_and_record(
    world: &mut CucumberWorld,
    accounts: Vec<AccountIdentity>,
    instruction_data: InstructionData,
    program_id: ProgramId,
    amount: u128,
) -> StepResult {
    let snapshot = scenario_snapshot(world).await?;
    let context = world.lez()?;
    let submitted_at_block = last_block(context).await?;
    let hash = context
        .send_program_transaction(accounts, instruction_data, program_id)
        .await?;

    let scenario = world.stake_mut()?;
    scenario.set_snapshot(snapshot);
    scenario.record_submission(SubmissionRecord {
        hash,
        amount,
        submitted_at_block,
    });
    Ok(())
}

/// Waits until `hash` appears in a block.
pub(super) async fn wait_for_inclusion(
    context: &LezScenarioContext,
    hash: HashType,
) -> StepResult {
    let poll = async {
        loop {
            let included = context
                .sequencer_client()
                .get_transaction(hash)
                .await
                .map_err(StepError::query_failed)?
                .is_some();
            if included {
                return Ok(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    };
    match tokio::time::timeout(WAIT_TIMEOUT, poll).await {
        Ok(result) => result,
        Err(_elapsed) => Err(StepError::Timeout {
            message: format!("transaction {hash} was not included within {WAIT_TIMEOUT:?}"),
        }),
    }
}

/// Waits until the chain has moved [`NON_INCLUSION_BLOCKS`] past the
/// submission tip and asserts the transaction is in none of them.
pub(super) async fn assert_not_included(
    context: &LezScenarioContext,
    submission: &SubmissionRecord,
) -> StepResult {
    let target = submission
        .submitted_at_block
        .saturating_add(NON_INCLUSION_BLOCKS);
    let poll = async {
        loop {
            if last_block(context).await? >= target {
                return Ok::<(), StepError>(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    };
    match tokio::time::timeout(WAIT_TIMEOUT, poll).await {
        Ok(result) => result?,
        Err(_elapsed) => {
            return Err(StepError::Timeout {
                message: format!(
                    "the chain did not reach block {target} within {WAIT_TIMEOUT:?} to prove \
                     non-inclusion"
                ),
            });
        }
    }

    let included = context
        .sequencer_client()
        .get_transaction(submission.hash)
        .await
        .map_err(StepError::query_failed)?;
    if let Some((_transaction, block_id)) = included {
        return Err(StepError::AssertionFailed {
            message: format!(
                "transaction {} was included in block {block_id}, expected it to be dropped",
                submission.hash
            ),
        });
    }
    Ok(())
}

/// Submits a fully signed, well-formed `Stake` and waits for its inclusion.
/// Used by setup steps whose registrations must succeed; the submission is
/// not recorded as the one under test.
pub(super) async fn submit_accepted_stake(
    context: &LezScenarioContext,
    funding_id: AccountId,
    ownership_id: AccountId,
    sequencer_key: SequencerKey,
    amount: u128,
) -> StepResult {
    let hash = context
        .send_program_transaction(
            vec![
                AccountIdentity::Public(funding_id),
                AccountIdentity::Public(ownership_id),
                AccountIdentity::PublicNoSign(system_accounts::sequencer_stake_config_account_id()),
            ],
            stake_instruction(sequencer_key, amount)?,
            programs::sequencer_stake().id(),
        )
        .await?;
    wait_for_inclusion(context, hash).await
}
