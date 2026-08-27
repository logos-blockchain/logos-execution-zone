//! Chain access shared by the stake lifecycle steps: account and config
//! queries, submission bookkeeping and the inclusion/non-inclusion waits.

use std::time::Duration;

use common::HashType;
use futures::future::try_join_all;
use lee::{Account, AccountId, PublicKey, program::Program};
use lee_core::program::{InstructionData, ProgramId};
use sequencer_core::{
    block_publisher::{Ed25519PublicKey, read_channel_state},
    config::BedrockConfig,
};
use sequencer_service_rpc::RpcClient as _;
use sequencer_stake_core::{SequencerEntry, SequencerKey, SequencerStakeConfig};
use wallet::AccountIdentity;

use super::super::wait_until;
use crate::{
    config::{self, UrlProtocol},
    cucumber::{
        context::LezScenarioContext,
        error::{StepError, StepResult},
        stake_scenario::{AccountsSnapshot, SubmissionRecord, stake_instruction},
        world::CucumberWorld,
    },
};

/// Cadence of the inclusion and non-inclusion polls.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Upper bound on every wait, in block periods; generous because a freshly
/// accredited key with no node behind it slows block production down to the
/// posting-turn reclaim.
const WAIT_TIMEOUT_BLOCKS: u32 = 60;

/// Blocks past the post-admission tip that prove a dropped transaction: the
/// builder pulls the whole mempool on every turn, so once two more blocks
/// exist at least one pull happened after admission and the transaction was
/// tried and dropped rather than still queued.
const NON_INCLUSION_BLOCKS: u64 = 2;

/// Upper bound on every wait, derived from the block cadence the deployed
/// stack was configured with.
const fn wait_timeout(context: &LezScenarioContext) -> Duration {
    context
        .block_create_timeout()
        .saturating_mul(WAIT_TIMEOUT_BLOCKS)
}

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
    let account = get_account(
        context,
        system_accounts::sequencer_stake_config_account_id(),
    )
    .await?;
    SequencerStakeConfig::from_bytes(account.data.as_ref()).ok_or_else(|| StepError::LogicalError {
        message: "the config account does not decode as a SequencerStakeConfig".to_owned(),
    })
}

/// Returns the config entry backing `sequencer_key`, if any.
pub(super) async fn config_entry(
    context: &LezScenarioContext,
    sequencer_key: SequencerKey,
) -> Result<Option<SequencerEntry>, StepError> {
    Ok(stake_config(context)
        .await?
        .entries
        .get(&sequencer_key)
        .copied())
}

/// Returns the first genesis-funded public account configured into the
/// scenario wallet, identified by its fixture-derived id so the choice does
/// not depend on the wallet's account iteration order.
pub(super) async fn first_configured_public_account(
    context: &LezScenarioContext,
) -> Result<AccountId, StepError> {
    let existing = context.existing_public_accounts().await?;
    crate::config::default_public_accounts_for_wallet()
        .iter()
        .map(|(private_key, _balance)| {
            AccountId::from(&PublicKey::new_from_private_key(private_key))
        })
        .find(|account_id| existing.contains(account_id))
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

/// Creates a fresh public account and asserts it starts out default-owned and
/// unclaimed.
pub(super) async fn create_unclaimed_account(
    context: &LezScenarioContext,
) -> Result<AccountId, StepError> {
    let account_id = context.new_public_account().await?;
    let account = get_account(context, account_id).await?;
    if account != Account::default() {
        return Err(StepError::AssertionFailed {
            message: "the fresh account does not start out default-owned and unclaimed".to_owned(),
        });
    }
    Ok(account_id)
}

/// Creates a fresh public account claimed for `authenticated_transfer` with
/// exactly `balance` on it, so it can act as a Stake mover's sender.
pub(super) async fn create_funded_account(
    context: &LezScenarioContext,
    balance: u128,
) -> Result<AccountId, StepError> {
    let funding_id = context.new_public_account().await?;
    let supply_id = first_configured_public_account(context).await?;
    context
        .public_transfer_to_new_account(supply_id, funding_id, balance)
        .await?;
    let funded = get_account(context, funding_id).await?.balance;
    if funded != balance {
        return Err(StepError::AssertionFailed {
            message: format!("the funding account holds {funded}, expected {balance}"),
        });
    }
    Ok(funding_id)
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
    account_ids.extend(scenario.second_funding_id().ok());
    account_ids.extend(scenario.second_ownership_id().ok());

    let accounts = try_join_all(account_ids.into_iter().map(|account_id| async move {
        Ok::<_, StepError>((account_id, get_account(context, account_id).await?))
    }))
    .await?;
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
    let hash = context
        .send_program_transaction(accounts, instruction_data, program_id)
        .await?;
    // Mempool admission is synchronous with the send reply, so a tip read
    // here is at or past the admission point and the non-inclusion window is
    // guaranteed to cover a post-admission mempool pull.
    let submitted_at_block = last_block(context).await?;

    let scenario = world.stake_mut()?;
    scenario.set_snapshot(snapshot);
    scenario.record_submission(SubmissionRecord {
        hash,
        amount,
        submitted_at_block,
    });
    Ok(())
}

/// Deploys `program`'s bytecode at runtime and waits until the deployment is
/// included, so the program is registered in state and usable as the target of
/// a later transaction. Test guests are not in the node's compiled-in program
/// set, so scenarios that exercise one deploy it first.
pub(super) async fn deploy_and_wait(context: &LezScenarioContext, program: &Program) -> StepResult {
    let hash = context.deploy_program(program.elf().to_vec()).await?;
    wait_for_inclusion(context, hash).await
}

/// Waits until `hash` appears in a block.
pub(super) async fn wait_for_inclusion(context: &LezScenarioContext, hash: HashType) -> StepResult {
    wait_until(
        POLL_INTERVAL,
        wait_timeout(context),
        format!("transaction {hash} to be included"),
        || async move {
            Ok(context
                .sequencer_client()
                .get_transaction(hash)
                .await
                .map_err(StepError::query_failed)?
                .map(|_included| ()))
        },
    )
    .await
}

/// Waits until the chain has moved [`NON_INCLUSION_BLOCKS`] past the
/// post-admission tip and asserts the transaction is in none of them.
pub(super) async fn assert_not_included(
    context: &LezScenarioContext,
    submission: &SubmissionRecord,
) -> StepResult {
    let target = submission
        .submitted_at_block
        .saturating_add(NON_INCLUSION_BLOCKS);
    wait_until(
        POLL_INTERVAL,
        wait_timeout(context),
        format!("the chain to reach block {target} proving non-inclusion"),
        || async move { Ok((last_block(context).await? >= target).then_some(())) },
    )
    .await?;

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

/// The block that included `hash`, or `None` while it is not included.
pub(super) async fn inclusion_block(
    context: &LezScenarioContext,
    hash: HashType,
) -> Result<Option<u64>, StepError> {
    Ok(context
        .sequencer_client()
        .get_transaction(hash)
        .await
        .map_err(StepError::query_failed)?
        .map(|(_transaction, block_id)| block_id))
}

/// Reads the live accredited keys (as raw key bytes) from the Bedrock channel
/// backing the stack, or `None` while the channel does not exist yet.
async fn live_accredited_keys(
    context: &LezScenarioContext,
) -> Result<Option<Vec<[u8; 32]>>, StepError> {
    let bedrock_config = BedrockConfig {
        channel_id: config::bedrock_channel_id(),
        node_url: config::addr_to_url(UrlProtocol::Http, context.bedrock().primary_api_addr())
            .map_err(|source| StepError::QueryFailedSource { source })?,
        funding_key: config::bedrock_funding_key(),
        auth: None,
        priority_fee: 10_000,
    };
    let state = read_channel_state(&bedrock_config)
        .await
        .map_err(|source| StepError::QueryFailedSource { source })?;
    Ok(state.map(|state| {
        state
            .accredited_keys
            .iter()
            .map(Ed25519PublicKey::to_bytes)
            .collect()
    }))
}

/// Waits until both `keys` are accredited on the Bedrock channel. With
/// `atomic` — the Stakes shared a block, so they finalize together, qualify
/// in the same discovery window and one `ChannelConfigOp` must admit both —
/// observing exactly one accredited key fails immediately as a split update.
pub(super) async fn wait_for_joint_accreditation(
    context: &LezScenarioContext,
    keys: [[u8; 32]; 2],
    atomic: bool,
) -> StepResult {
    wait_until(
        POLL_INTERVAL,
        wait_timeout(context),
        "both sequencer keys to join the live committee",
        || async move {
            let Some(live) = live_accredited_keys(context).await? else {
                return Ok(None);
            };
            let accredited = keys.map(|key| live.contains(&key));
            if atomic && accredited.iter().any(|seen| *seen) && !accredited.iter().all(|seen| *seen)
            {
                return Err(StepError::AssertionFailed {
                    message: "one sequencer key is accredited without the other, but their \
                              Stakes shared a block so a single committee update must admit both"
                        .to_owned(),
                });
            }
            Ok(accredited.iter().all(|seen| *seen).then_some(()))
        },
    )
    .await
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
