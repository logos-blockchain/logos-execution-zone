#![expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers use the framework's mutable-world signature"
)]

use cucumber::{gherkin::Step, given};
use lee::Account;
use wallet::AccountIdentity;

use super::{
    super::log_step,
    helpers::{
        config_entry, deploy_and_wait, first_configured_public_account, get_account, stake_config,
        submit_accepted_stake, wait_for_inclusion,
    },
};
use crate::cucumber::{
    error::{StepError, StepResult},
    stake_scenario::{StakeScenario, simple_balance_transfer_instruction, transfer_instruction},
    world::CucumberWorld,
};

/// Byte string that is not an Ed25519 curve point, matching the L0 test
/// `a_non_curve_point_is_not_a_sequencer_key`.
const OFF_CURVE_BYTES: [u8; 32] = [2; 32];

#[given("the sequencer_stake config account is at the default minimum stake")]
async fn config_account_at_default_minimum(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let minimum = stake_config(world.lez()?).await?.minimum_sequencer_stake;
    if minimum != system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE {
        return Err(StepError::AssertionFailed {
            message: format!(
                "config minimum is {minimum}, expected the default {}",
                system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE
            ),
        });
    }
    world.set_stake(StakeScenario::new(minimum))
}

#[given("a sequencer key with no config entry")]
async fn sequencer_key_has_no_entry(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let sequencer_key = world.stake()?.sequencer_key();
    if config_entry(world.lez()?, sequencer_key).await?.is_some() {
        return Err(StepError::AssertionFailed {
            message: "the sequencer key already has a config entry".to_owned(),
        });
    }
    Ok(())
}

#[given("a default-owned, unclaimed ownership account for the sequencer key")]
async fn ownership_account_is_unclaimed(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let context = world.lez()?;
    let ownership_id = context.new_public_account().await?;
    let account = get_account(context, ownership_id).await?;
    if account != Account::default() {
        return Err(StepError::AssertionFailed {
            message: "the ownership account does not start out fresh and unclaimed".to_owned(),
        });
    }
    world.stake_mut()?.set_ownership_id(ownership_id);
    Ok(())
}

#[given(expr = "a funding account holding {string}")]
async fn fund_funding_account(
    world: &mut CucumberWorld,
    step: &Step,
    expression: String,
) -> StepResult {
    log_step(step);
    let balance = world.stake()?.amount(&expression)?;
    let context = world.lez()?;
    let funding_id = context.new_public_account().await?;
    let supply_id = first_configured_public_account(context).await?;
    // Claims the fresh account for authenticated_transfer with exactly
    // `balance` on it, so it can act as the Stake mover's sender.
    context
        .public_transfer_to_new_account(supply_id, funding_id, balance)
        .await?;
    let funded = get_account(context, funding_id).await?.balance;
    if funded != balance {
        return Err(StepError::AssertionFailed {
            message: format!("the funding account holds {funded}, expected {balance}"),
        });
    }
    world.stake_mut()?.set_funding_id(funding_id);
    Ok(())
}

#[given("the ownership account is already claimed by the authenticated_transfer program")]
async fn ownership_account_claimed_by_other_program(
    world: &mut CucumberWorld,
    step: &Step,
) -> StepResult {
    log_step(step);
    let ownership_id = world.stake()?.ownership_id()?;
    let context = world.lez()?;
    let supply_id = first_configured_public_account(context).await?;
    // A transfer with the recipient signing claims a default-owned recipient
    // for authenticated_transfer — the only foreign owner reachable through
    // deployed programs.
    context
        .public_transfer_to_new_account(supply_id, ownership_id, 1)
        .await?;
    let owner = get_account(context, ownership_id).await?.program_owner;
    if owner != programs::authenticated_transfer().id().into() {
        return Err(StepError::AssertionFailed {
            message: format!(
                "the ownership account is owned by {owner}, expected authenticated_transfer"
            ),
        });
    }
    Ok(())
}

#[given("a second sequencer key staked through its own ownership account")]
async fn stake_second_sequencer_key(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let funding_id = scenario.funding_id()?;
    let second_sequencer_key = scenario.second_sequencer_key();
    let amount = scenario.minimum_stake();
    let context = world.lez()?;
    let second_ownership_id = context.new_public_account().await?;
    submit_accepted_stake(
        context,
        funding_id,
        second_ownership_id,
        second_sequencer_key,
        amount,
    )
    .await?;
    let owner = get_account(context, second_ownership_id)
        .await?
        .program_owner;
    if owner != programs::sequencer_stake().id().into() {
        return Err(StepError::AssertionFailed {
            message: "staking the second sequencer key did not claim its ownership account"
                .to_owned(),
        });
    }
    world
        .stake_mut()?
        .set_second_ownership_id(second_ownership_id);
    Ok(())
}

#[given("32 bytes that are not an Ed25519 curve point")]
fn off_curve_key_bytes(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    world.stake_mut()?.set_off_curve_bytes(OFF_CURVE_BYTES);
    Ok(())
}

#[given("the stake_chain_caller test program is deployed")]
async fn deploy_stake_chain_caller(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    deploy_and_wait(world.lez()?, &test_programs::stake_chain_caller()).await
}

#[given("the simple_balance_transfer test program is deployed")]
async fn deploy_simple_balance_transfer(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    deploy_and_wait(world.lez()?, &test_programs::simple_balance_transfer()).await
}

#[given(expr = "a funding account owned by the simple_balance_transfer program holding {string}")]
async fn fund_account_owned_by_simple_mover(
    world: &mut CucumberWorld,
    step: &Step,
    expression: String,
) -> StepResult {
    log_step(step);
    let balance = world.stake()?.amount(&expression)?;
    let context = world.lez()?;
    let simple_mover_id = test_programs::simple_balance_transfer().id();

    // A fresh default account the scenario wallet can sign for.
    let funding_id = context.new_public_account().await?;

    // Claim it under simple_balance_transfer: its one-account branch claims a
    // signed default account and ignores the instruction value.
    let claim_hash = context
        .send_program_transaction(
            vec![AccountIdentity::Public(funding_id)],
            simple_balance_transfer_instruction(0)?,
            simple_mover_id,
        )
        .await?;
    wait_for_inclusion(context, claim_hash).await?;
    let owner = get_account(context, funding_id).await?.program_owner;
    if owner != simple_mover_id.into() {
        return Err(StepError::AssertionFailed {
            message: format!(
                "the funding account is owned by {owner}, expected simple_balance_transfer"
            ),
        });
    }

    // Credit it from a genesis account. The account is already claimed, so the
    // authenticated_transfer only moves balance and does not re-claim it —
    // ownership stays with simple_balance_transfer, which is what lets it debit
    // the account as the Stake mover.
    let supply_id = first_configured_public_account(context).await?;
    let fund_hash = context
        .send_program_transaction(
            vec![
                AccountIdentity::Public(supply_id),
                AccountIdentity::PublicNoSign(funding_id),
            ],
            transfer_instruction(balance)?,
            programs::authenticated_transfer().id(),
        )
        .await?;
    wait_for_inclusion(context, fund_hash).await?;
    let funded = get_account(context, funding_id).await?.balance;
    if funded != balance {
        return Err(StepError::AssertionFailed {
            message: format!("the funding account holds {funded}, expected {balance}"),
        });
    }

    world.stake_mut()?.set_funding_id(funding_id);
    Ok(())
}
