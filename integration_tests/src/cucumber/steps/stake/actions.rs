use cucumber::{gherkin::Step, when};
use lee::AccountId;
use wallet::AccountIdentity;

use super::{
    super::log_step,
    helpers::{first_configured_public_account, get_account, submit_and_record},
};
use crate::cucumber::{
    error::{StepError, StepResult},
    stake_scenario::{
        confirm_stake_instruction, raw_stake_instruction, stake_instruction, transfer_instruction,
    },
    world::CucumberWorld,
};

/// The standard `Stake` account list: signing funding and ownership accounts,
/// then the unsigned stake funds PDA of the ownership account and the unsigned
/// config account.
fn stake_accounts(funding_id: AccountId, ownership_id: AccountId) -> Vec<AccountIdentity> {
    vec![
        AccountIdentity::Public(funding_id),
        AccountIdentity::Public(ownership_id),
        AccountIdentity::PublicNoSign(system_accounts::stake_funds_account_id(&ownership_id)),
        AccountIdentity::PublicNoSign(system_accounts::sequencer_stake_config_account_id()),
    ]
}

/// Resolves the amount expression, builds the scenario's `Stake` instruction
/// and submits it with `accounts` as the pre-state list.
async fn submit_stake_with_accounts(
    world: &mut CucumberWorld,
    expression: &str,
    accounts: Vec<AccountIdentity>,
) -> StepResult {
    let scenario = world.stake()?;
    let amount = scenario.amount(expression)?;
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

#[when(expr = "a Stake of {string} is submitted")]
async fn submit_stake(world: &mut CucumberWorld, step: &Step, expression: String) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let accounts = stake_accounts(scenario.funding_id()?, scenario.ownership_id()?);
    submit_stake_with_accounts(world, &expression, accounts).await
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
    let accounts = vec![
        AccountIdentity::Public(scenario.funding_id()?),
        AccountIdentity::PublicNoSign(ownership_id),
        AccountIdentity::PublicNoSign(system_accounts::stake_funds_account_id(&ownership_id)),
        AccountIdentity::PublicNoSign(system_accounts::sequencer_stake_config_account_id()),
    ];
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
    let ownership_id = scenario.ownership_id()?;
    let accounts = vec![
        AccountIdentity::Public(scenario.funding_id()?),
        AccountIdentity::Public(ownership_id),
        AccountIdentity::PublicNoSign(system_accounts::stake_funds_account_id(&ownership_id)),
        AccountIdentity::PublicNoSign(scenario.second_ownership_id()?),
    ];
    submit_stake_with_accounts(world, &expression, accounts).await
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
    let canonical = stake_accounts(scenario.funding_id()?, scenario.ownership_id()?);
    // Deterministic, unsigned filler accounts pad the pre-state list past the
    // canonical four; the program rejects on the account count before
    // touching them. The high byte pattern keeps them clear of other fixed
    // test account ids.
    let filler_account = |index: usize| {
        u8::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(0xE0))
            .map(|byte| AccountIdentity::PublicNoSign(AccountId::new([byte; 32])))
            .ok_or_else(|| StepError::InvalidArgument {
                message: format!("unsupported pre-state account count {count}"),
            })
    };
    let accounts = (0..count)
        .map(|index| {
            canonical
                .get(index)
                .map_or_else(|| filler_account(index), |identity| Ok(identity.clone()))
        })
        .collect::<Result<Vec<_>, StepError>>()?;
    submit_stake_with_accounts(world, &expression, accounts).await
}

#[when("a ConfirmStake matching the current funds balance is submitted as a top-level transaction")]
async fn submit_confirm_stake_top_level(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let ownership_id = scenario.ownership_id()?;
    // The expected balance matches the stake funds account, the account
    // ConfirmStake reads, so the balance check could not reject it. The
    // caller check is the handler's first assert and fires before the account
    // list is looked at; the ownership account signs only because the wallet
    // needs a signer for any top-level transaction, since the funds PDA has
    // no key.
    let balance = get_account(world.lez()?, scenario.funds_id()?)
        .await?
        .balance;
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
    let ownership_id = world.stake()?.ownership_id()?;
    // The recipient deliberately does not sign: a donation is a plain
    // transfer someone else pushes at the account. The donor is a genesis
    // supply account rather than the funding account: unlike Stake, a plain
    // transfer is fee-charged, and the funding account holds only its stake.
    let donor_id = first_configured_public_account(world.lez()?).await?;
    let accounts = vec![
        AccountIdentity::Public(donor_id),
        AccountIdentity::PublicNoSign(ownership_id),
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
