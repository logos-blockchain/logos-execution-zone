use cucumber::{gherkin::Step, when};
use lee_core::account::Actor;
use wallet::{AccountIdentity, AccountMention};

use super::{
    super::log_step,
    helpers::{
        first_configured_public_account, has_stake_record, stake_accounts, submit_and_record,
        submit_and_record_paid_by,
    },
};
use crate::cucumber::{
    error::{StepError, StepResult},
    stake_scenario::{raw_stake_message, relayed_message, stake, stake_message, transfer_message},
    world::CucumberWorld,
};

/// Resolves the amount expression, builds the scenario's `Stake` message and
/// submits it over `accounts`, delivered to the first of them.
async fn submit_stake_with_accounts(
    world: &mut CucumberWorld,
    expression: &str,
    accounts: Vec<AccountMention>,
) -> StepResult {
    let scenario = world.stake()?;
    let amount = scenario.amount(expression)?;
    let has_record = has_stake_record(world.lez()?, scenario.ownership_id()?).await?;
    let message = stake_message(
        scenario.sequencer_key(),
        amount,
        has_record,
        scenario.funding_id()?,
    )?;
    submit_and_record(world, accounts, message, amount).await
}

#[when(expr = "a Stake of {string} is submitted")]
async fn submit_stake(world: &mut CucumberWorld, step: &Step, expression: String) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let accounts = stake_accounts(scenario.funding_id()?, scenario.ownership_id()?);
    submit_stake_with_accounts(world, &expression, accounts).await
}

#[when(expr = "a Stake of {string} is sent from the scripted test program")]
async fn submit_stake_from_another_actor(
    world: &mut CucumberWorld,
    step: &Step,
    expression: String,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let amount = scenario.amount(&expression)?;
    let ownership_id = scenario.ownership_id()?;
    let funding_id = scenario.funding_id()?;
    let relay_program_id = scenario.deployed_program(&test_programs::scripted())?;
    let context = world.lez()?;
    // The transaction is delivered to a fresh account's actor under the
    // scripted program, whose script sends an otherwise well-formed Stake on
    // to the ownership account's sequencer_stake actor. That actor sees the
    // relay, not the transaction, as its sender, so sequencer_stake's
    // root-origin guard is the only assert that can reject it.
    let relay_id = context.new_public_account().await?;
    let has_record = has_stake_record(context, ownership_id).await?;
    let stake_actor = Actor::new(ownership_id, programs::sequencer_stake_account_id());
    let message = relayed_message(
        stake_actor,
        &stake(scenario.sequencer_key(), amount, has_record, funding_id),
    )?;
    // The relay heads the declared accounts as the root; the Stake's own
    // canonical accounts follow, since the relayed Stake reaches all of them.
    let mut accounts =
        vec![AccountIdentity::Public(relay_id).select_program_actor_state(relay_program_id)];
    accounts.extend(stake_accounts(funding_id, ownership_id));
    // The transaction is not delivered to sequencer_stake, so it is
    // fee-charged. The funding account holds only its stake, far below the
    // wallet's default fee reserve, so a genesis supply account pays instead;
    // that also keeps the fee off the accounts the scenario asserts on.
    let payer_id = first_configured_public_account(context).await?;
    submit_and_record_paid_by(world, accounts, 0, message, Some(payer_id), amount).await
}

#[when(expr = "a Stake of {string} is submitted without the ownership account's signature")]
async fn submit_stake_unsigned_ownership(
    world: &mut CucumberWorld,
    step: &Step,
    expression: String,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let ownership_id = scenario.ownership_id()?;
    let mut accounts = stake_accounts(scenario.funding_id()?, ownership_id);
    accounts[0] = AccountIdentity::PublicNoSign(ownership_id)
        .select_program_actor_state(programs::sequencer_stake_account_id());
    submit_stake_with_accounts(world, &expression, accounts).await
}

#[when(
    expr = "a Stake of {string} is submitted with the second ownership account standing in for \
            the config account"
)]
async fn submit_stake_with_ownership_as_config(
    world: &mut CucumberWorld,
    step: &Step,
    expression: String,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let mut accounts = stake_accounts(scenario.funding_id()?, scenario.ownership_id()?);
    accounts[3] = AccountIdentity::PublicNoSign(scenario.second_ownership_id()?)
        .select_program_actor_state(programs::sequencer_stake_account_id());
    submit_stake_with_accounts(world, &expression, accounts).await
}

#[when(expr = "a Stake of {string} is submitted declaring only its first {int} accounts")]
async fn submit_stake_with_account_count(
    world: &mut CucumberWorld,
    step: &Step,
    expression: String,
    count: usize,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let canonical = stake_accounts(scenario.funding_id()?, scenario.ownership_id()?);
    if count == 0 || count >= canonical.len() {
        return Err(StepError::InvalidArgument {
            message: format!("unsupported declared account count {count}"),
        });
    }
    let accounts = canonical.into_iter().take(count).collect();
    submit_stake_with_accounts(world, &expression, accounts).await
}

#[when("a Stake carrying the off-curve key bytes is submitted")]
async fn submit_stake_with_off_curve_key(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let amount = scenario.minimum_stake();
    let funding_id = scenario.funding_id()?;
    let accounts = stake_accounts(funding_id, scenario.ownership_id()?);
    let message = raw_stake_message(scenario.off_curve_bytes()?, amount, funding_id)?;
    submit_and_record(world, accounts, message, amount).await
}

#[when(expr = "a donation of {int} to the unclaimed ownership account is submitted")]
async fn submit_donation_to_unclaimed_ownership(
    world: &mut CucumberWorld,
    step: &Step,
    donation: u128,
) -> StepResult {
    log_step(step);
    let ownership_id = world.stake()?.ownership_id()?;
    // The recipient deliberately does not sign: a donation is a plain
    // transfer someone else pushes at the account. The donor is a genesis
    // supply account rather than the funding account: unlike Stake, a plain
    // transfer is fee-charged, and the funding account holds only its stake.
    let donor_id = first_configured_public_account(world.lez()?).await?;
    let accounts = vec![
        AccountIdentity::Public(donor_id).balance(),
        AccountIdentity::PublicNoSign(ownership_id).balance(),
    ];
    let message = transfer_message(ownership_id, donation)?;
    submit_and_record(world, accounts, message, donation).await
}
