use cucumber::{gherkin::Step, when};
use lee::AccountId;
use wallet::AccountIdentity;

use super::{
    super::log_step,
    helpers::{get_account, last_block, scenario_snapshot, submit_and_record},
};
use crate::cucumber::{
    error::{StepError, StepResult},
    stake_scenario::{
        SubmissionRecord, chain_caller_instruction, confirm_stake_instruction,
        raw_stake_instruction, simple_balance_transfer_instruction, stake_instruction,
        stake_instruction_with_mover, transfer_instruction,
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

#[when(
    expr = "a Stake of {string} is submitted as a chained call through the stake_chain_caller \
            program"
)]
async fn submit_stake_as_chained_call(
    world: &mut CucumberWorld,
    step: &Step,
    expression: String,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let amount = scenario.amount(&expression)?;
    // A well-formed Stake, submitted to the chain-caller program instead of
    // top-level: sequencer_stake's `caller_program_id.is_none()` guard is the
    // only thing that can reject it.
    let forwarded = stake_instruction(scenario.sequencer_key(), amount)?;
    let instruction = chain_caller_instruction(programs::sequencer_stake().id(), forwarded)?;
    let accounts = stake_accounts(scenario.funding_id()?, scenario.ownership_id()?);
    submit_and_record(
        world,
        accounts,
        instruction,
        test_programs::stake_chain_caller().id(),
        amount,
    )
    .await
}

#[when(expr = "a Stake of {string} is submitted with simple_balance_transfer as the mover")]
async fn submit_stake_with_simple_mover(
    world: &mut CucumberWorld,
    step: &Step,
    expression: String,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let amount = scenario.amount(&expression)?;
    // simple_balance_transfer moves `amount` from the (mover-owned) funding
    // account into the ownership account, standing in for authenticated_transfer
    // as a different mover.
    let instruction = stake_instruction_with_mover(
        scenario.sequencer_key(),
        amount,
        test_programs::simple_balance_transfer().id(),
        simple_balance_transfer_instruction(amount)?,
    )?;
    let accounts = stake_accounts(scenario.funding_id()?, scenario.ownership_id()?);
    submit_and_record(
        world,
        accounts,
        instruction,
        programs::sequencer_stake().id(),
        amount,
    )
    .await
}

#[when(expr = "a Stake of {string} is submitted for each sequencer key back-to-back")]
async fn submit_stakes_for_both_keys(
    world: &mut CucumberWorld,
    step: &Step,
    expression: String,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let amount = scenario.amount(&expression)?;
    let first_instruction = stake_instruction(scenario.sequencer_key(), amount)?;
    let first_accounts = stake_accounts(scenario.funding_id()?, scenario.ownership_id()?);
    let second_instruction = stake_instruction(scenario.second_sequencer_key(), amount)?;
    let second_accounts = stake_accounts(
        scenario.second_funding_id()?,
        scenario.second_ownership_id()?,
    );

    let snapshot = scenario_snapshot(world).await?;
    let context = world.lez()?;
    // Both are admitted before either can be included, so one builder pull
    // tries both against the shared config account. The signing pairs are
    // disjoint, so the second submission does not depend on the first.
    let program_id = programs::sequencer_stake().id();
    let first_hash = context
        .send_program_transaction(first_accounts, first_instruction, program_id)
        .await?;
    let second_hash = context
        .send_program_transaction(second_accounts, second_instruction, program_id)
        .await?;
    let submitted_at_block = last_block(context).await?;

    let record = world.stake_mut()?;
    record.set_snapshot(snapshot);
    record.record_submission(SubmissionRecord {
        hash: first_hash,
        amount,
        submitted_at_block,
    });
    record.record_second_submission(SubmissionRecord {
        hash: second_hash,
        amount,
        submitted_at_block,
    });
    Ok(())
}

#[when(expr = "a Stake of {string} is submitted with the mover told to deposit one coin {word}")]
async fn submit_stake_with_skewed_mover(
    world: &mut CucumberWorld,
    step: &Step,
    expression: String,
    direction: String,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let amount = scenario.amount(&expression)?;
    // The mover instruction data is caller-controlled and opaque to
    // sequencer_stake, so authenticated_transfer itself plays the bad mover:
    // it deposits one coin off the amount the Stake declares.
    let mover_amount = match direction.as_str() {
        "less" => amount.checked_sub(1),
        "more" => amount.checked_add(1),
        other => {
            return Err(StepError::InvalidArgument {
                message: format!("unsupported mover skew '{other}', expected 'less' or 'more'"),
            });
        }
    }
    .ok_or_else(|| StepError::InvalidArgument {
        message: format!("mover amount one coin {direction} than {amount} is out of range"),
    })?;
    let instruction = stake_instruction_with_mover(
        scenario.sequencer_key(),
        amount,
        programs::authenticated_transfer().id(),
        transfer_instruction(mover_amount)?,
    )?;
    let accounts = stake_accounts(scenario.funding_id()?, scenario.ownership_id()?);
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
    let accounts = vec![
        AccountIdentity::Public(scenario.funding_id()?),
        AccountIdentity::PublicNoSign(scenario.ownership_id()?),
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
    let accounts = vec![
        AccountIdentity::Public(scenario.funding_id()?),
        AccountIdentity::Public(scenario.ownership_id()?),
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
    // canonical three; the program rejects on the account count before
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

#[when(
    "a ConfirmStake matching the current ownership balance is submitted as a chained call \
     through the stake_chain_caller program"
)]
async fn submit_confirm_stake_as_chained_call(
    world: &mut CucumberWorld,
    step: &Step,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let ownership_id = scenario.ownership_id()?;
    // The expected balance matches the current one, so ConfirmStake's caller
    // check — the caller is stake_chain_caller, not sequencer_stake — is the
    // only assert that can reject it.
    let balance = get_account(world.lez()?, ownership_id).await?.balance;
    let forwarded = confirm_stake_instruction(balance)?;
    let instruction = chain_caller_instruction(programs::sequencer_stake().id(), forwarded)?;
    let accounts = vec![AccountIdentity::Public(ownership_id)];
    submit_and_record(
        world,
        accounts,
        instruction,
        test_programs::stake_chain_caller().id(),
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
