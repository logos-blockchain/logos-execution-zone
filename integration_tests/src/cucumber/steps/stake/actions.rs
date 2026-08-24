use cucumber::{gherkin::Step, when};
use lee::AccountId;
use wallet::AccountIdentity;

use super::{
    super::log_step,
    helpers::{get_account, submit_and_record},
};
use crate::cucumber::{
    error::{StepError, StepResult},
    stake_scenario::{
        EXTRA_ACCOUNT_ID, confirm_stake_instruction, raw_stake_instruction, stake_instruction,
        transfer_instruction,
    },
    world::CucumberWorld,
};

/// The standard `Stake` account list: signing funding and ownership accounts
/// plus the unsigned config account.
fn stake_accounts(funding_id: AccountId, ownership_id: AccountId) -> Vec<AccountIdentity> {
    vec![
        AccountIdentity::Public(funding_id),
        AccountIdentity::Public(ownership_id),
        AccountIdentity::PublicNoSign(system_accounts::sequencer_stake_config_account_id()),
    ]
}

#[when(expr = "a Stake of {string} is submitted")]
async fn submit_stake(world: &mut CucumberWorld, step: &Step, expression: String) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let amount = scenario.amount(&expression)?;
    let accounts = stake_accounts(scenario.funding_id()?, scenario.ownership_id()?);
    let instruction = stake_instruction(scenario.sequencer_key(), amount)?;
    submit_and_record(
        world,
        accounts,
        instruction,
        programs::sequencer_stake().id(),
        amount,
    )
    .await
}

#[when(expr = "a Stake of {string} is submitted without the ownership account's signature")]
async fn submit_stake_unsigned_ownership(
    world: &mut CucumberWorld,
    step: &Step,
    expression: String,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let amount = scenario.amount(&expression)?;
    let accounts = vec![
        AccountIdentity::Public(scenario.funding_id()?),
        AccountIdentity::PublicNoSign(scenario.ownership_id()?),
        AccountIdentity::PublicNoSign(system_accounts::sequencer_stake_config_account_id()),
    ];
    let instruction = stake_instruction(scenario.sequencer_key(), amount)?;
    submit_and_record(
        world,
        accounts,
        instruction,
        programs::sequencer_stake().id(),
        amount,
    )
    .await
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
    let amount = scenario.amount(&expression)?;
    let accounts = vec![
        AccountIdentity::Public(scenario.funding_id()?),
        AccountIdentity::Public(scenario.ownership_id()?),
        AccountIdentity::PublicNoSign(scenario.second_ownership_id()?),
    ];
    let instruction = stake_instruction(scenario.sequencer_key(), amount)?;
    submit_and_record(
        world,
        accounts,
        instruction,
        programs::sequencer_stake().id(),
        amount,
    )
    .await
}

#[when(expr = "a Stake of {string} is submitted with {int} pre-state accounts")]
async fn submit_stake_with_account_count(
    world: &mut CucumberWorld,
    step: &Step,
    expression: String,
    count: usize,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let amount = scenario.amount(&expression)?;
    let funding_id = scenario.funding_id()?;
    let ownership_id = scenario.ownership_id()?;
    let accounts = match count {
        2 => vec![
            AccountIdentity::Public(funding_id),
            AccountIdentity::Public(ownership_id),
        ],
        4 => vec![
            AccountIdentity::Public(funding_id),
            AccountIdentity::Public(ownership_id),
            AccountIdentity::PublicNoSign(system_accounts::sequencer_stake_config_account_id()),
            AccountIdentity::PublicNoSign(AccountId::new(EXTRA_ACCOUNT_ID)),
        ],
        other => {
            return Err(StepError::InvalidArgument {
                message: format!("unsupported pre-state account count {other}"),
            });
        }
    };
    let instruction = stake_instruction(scenario.sequencer_key(), amount)?;
    submit_and_record(
        world,
        accounts,
        instruction,
        programs::sequencer_stake().id(),
        amount,
    )
    .await
}

#[when(
    "a ConfirmStake matching the current ownership balance is submitted as a top-level transaction"
)]
async fn submit_confirm_stake_top_level(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let ownership_id = scenario.ownership_id()?;
    // The expected balance matches the current one so the caller check is the
    // only assert that can reject it.
    let balance = get_account(world.lez()?, ownership_id).await?.balance;
    let accounts = vec![AccountIdentity::Public(ownership_id)];
    let instruction = confirm_stake_instruction(balance)?;
    submit_and_record(
        world,
        accounts,
        instruction,
        programs::sequencer_stake().id(),
        0,
    )
    .await
}

#[when("a Stake carrying the off-curve key bytes is submitted")]
async fn submit_stake_with_off_curve_key(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let amount = scenario.minimum_stake();
    let accounts = stake_accounts(scenario.funding_id()?, scenario.ownership_id()?);
    let instruction = raw_stake_instruction(scenario.off_curve_bytes()?, amount)?;
    submit_and_record(
        world,
        accounts,
        instruction,
        programs::sequencer_stake().id(),
        amount,
    )
    .await
}

#[when(expr = "a donation of {int} to the unclaimed ownership account is submitted")]
async fn submit_donation_to_unclaimed_ownership(
    world: &mut CucumberWorld,
    step: &Step,
    donation: u128,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    // The recipient deliberately does not sign: a donation is a plain
    // transfer someone else pushes at the account.
    let accounts = vec![
        AccountIdentity::Public(scenario.funding_id()?),
        AccountIdentity::PublicNoSign(scenario.ownership_id()?),
    ];
    let instruction = transfer_instruction(donation)?;
    submit_and_record(
        world,
        accounts,
        instruction,
        programs::authenticated_transfer().id(),
        donation,
    )
    .await
}
