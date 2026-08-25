#![expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers use the framework's mutable-world signature"
)]

use cucumber::{gherkin::Step, then};
use futures::future::try_join_all;
use lee::Account;
use sequencer_stake_core::{SequencerEntry, SequencerKey, StakeRecord};

use super::{
    super::log_step,
    helpers::{assert_not_included, config_entry, get_account, wait_for_inclusion},
};
use crate::cucumber::{
    error::{StepError, StepResult},
    stake_scenario::raw_key_instruction_fails_to_decode,
    world::CucumberWorld,
};

/// Returns the config entry backing the scenario's sequencer key, or an
/// assertion failure if there is none.
async fn required_entry(world: &CucumberWorld) -> Result<SequencerEntry, StepError> {
    config_entry(world.lez()?, world.stake()?.sequencer_key())
        .await?
        .ok_or_else(|| StepError::AssertionFailed {
            message: "the config has no entry for the sequencer key".to_owned(),
        })
}

#[then("the stake transaction is accepted")]
async fn stake_transaction_accepted(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let hash = world.stake()?.last_submission()?.hash;
    wait_for_inclusion(world.lez()?, hash).await
}

#[then("the stake transaction is not included in a block")]
#[then("the donation transaction is not included in a block")]
async fn transaction_not_included(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let context = world.lez()?;
    let submission = world.stake()?.last_submission()?;
    assert_not_included(context, submission).await
}

#[then("the config entry tracks the staked amount with no pending unstake")]
async fn entry_tracks_staked_amount(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let amount = world.stake()?.last_submission()?.amount;
    let entry = required_entry(world).await?;
    if entry.total_staked != amount || entry.total_pending_unstake != 0 {
        return Err(StepError::AssertionFailed {
            message: format!(
                "the entry tracks {} staked with {} pending unstake, expected {amount} and 0",
                entry.total_staked, entry.total_pending_unstake
            ),
        });
    }
    Ok(())
}

#[then("the config entry points at the ownership account")]
async fn entry_points_at_ownership_account(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let ownership_id = world.stake()?.ownership_id()?;
    let entry = required_entry(world).await?;
    if entry.account_id != ownership_id {
        return Err(StepError::AssertionFailed {
            message: format!(
                "the entry points at {:?}, expected the ownership account {ownership_id:?}",
                entry.account_id
            ),
        });
    }
    Ok(())
}

#[then("the config has no entry for the sequencer key")]
async fn config_has_no_entry(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let sequencer_key = world.stake()?.sequencer_key();
    if config_entry(world.lez()?, sequencer_key).await?.is_some() {
        return Err(StepError::AssertionFailed {
            message: "the config carries an entry for the sequencer key, expected none".to_owned(),
        });
    }
    Ok(())
}

#[then(
    "the ownership account is claimed by sequencer_stake backing the sequencer key with no \
     pending unstake"
)]
async fn ownership_account_is_claimed(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let account = get_account(world.lez()?, scenario.ownership_id()?).await?;
    if account.program_owner != programs::sequencer_stake().id().into() {
        return Err(StepError::AssertionFailed {
            message: "the ownership account is not owned by sequencer_stake".to_owned(),
        });
    }
    let record = StakeRecord::from_bytes(account.data.as_ref()).ok_or_else(|| {
        StepError::AssertionFailed {
            message: "the ownership account data does not decode as a StakeRecord".to_owned(),
        }
    })?;
    if record.sequencer_key != scenario.sequencer_key() || record.pending_unstake.is_some() {
        return Err(StepError::AssertionFailed {
            message: format!(
                "the StakeRecord does not carry the sequencer key with no pending unstake: \
                 {record:?}"
            ),
        });
    }
    Ok(())
}

#[then("the ownership account is not claimed")]
async fn ownership_account_is_not_claimed(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let ownership_id = world.stake()?.ownership_id()?;
    let account = get_account(world.lez()?, ownership_id).await?;
    if account.program_owner != Account::default().program_owner {
        return Err(StepError::AssertionFailed {
            message: "the ownership account is claimed, expected it to stay default-owned"
                .to_owned(),
        });
    }
    Ok(())
}

#[then("the ownership account balance increased by the staked amount")]
async fn ownership_balance_increased(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let ownership_id = scenario.ownership_id()?;
    let balance_before = scenario.snapshot()?.account(ownership_id)?.balance;
    let expected = balance_before
        .checked_add(scenario.last_submission()?.amount)
        .ok_or_else(|| StepError::AssertionFailed {
            message: "expected ownership balance overflows".to_owned(),
        })?;
    let observed = get_account(world.lez()?, ownership_id).await?.balance;
    if observed != expected {
        return Err(StepError::AssertionFailed {
            message: format!("the ownership balance is {observed}, expected {expected}"),
        });
    }
    Ok(())
}

#[then("the funding account balance decreased by the staked amount")]
async fn funding_balance_decreased(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let funding_id = scenario.funding_id()?;
    let balance_before = scenario.snapshot()?.account(funding_id)?.balance;
    let expected = balance_before
        .checked_sub(scenario.last_submission()?.amount)
        .ok_or_else(|| StepError::AssertionFailed {
            message: "expected funding balance underflows".to_owned(),
        })?;
    let observed = get_account(world.lez()?, funding_id).await?.balance;
    if observed != expected {
        return Err(StepError::AssertionFailed {
            message: format!("the funding balance is {observed}, expected {expected}"),
        });
    }
    Ok(())
}

#[then("the stake accounts are unchanged")]
async fn stake_accounts_are_unchanged(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let context = world.lez()?;
    let snapshot = world.stake()?.snapshot()?;
    let current = try_join_all(
        snapshot
            .accounts()
            .iter()
            .map(|(account_id, before)| async move {
                Ok::<_, StepError>((
                    *account_id,
                    before,
                    get_account(context, *account_id).await?,
                ))
            }),
    )
    .await?;
    for (account_id, before, after) in current {
        if after != *before {
            return Err(StepError::AssertionFailed {
                message: format!(
                    "account {account_id} differs from its pre-submission snapshot: \
                     {before:?} -> {after:?}"
                ),
            });
        }
    }
    Ok(())
}

#[then("the bytes are not decodable as a SequencerKey")]
fn bytes_are_not_a_sequencer_key(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let key_bytes = world.stake()?.off_curve_bytes()?;
    if SequencerKey::new(key_bytes).is_some() {
        return Err(StepError::AssertionFailed {
            message: "the off-curve bytes decode as a SequencerKey".to_owned(),
        });
    }
    Ok(())
}

#[then("a StakeRecord carrying the bytes fails to decode")]
fn stake_record_with_bytes_fails_to_decode(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let key_bytes = world.stake()?.off_curve_bytes()?;
    // 32 key bytes then a `None` discriminant: a `StakeRecord` with no
    // pending unstake.
    let record_bytes = [&key_bytes[..], &[0_u8][..]].concat();
    if StakeRecord::from_bytes(&record_bytes).is_some() {
        return Err(StepError::AssertionFailed {
            message: "a StakeRecord carrying the off-curve bytes decodes".to_owned(),
        });
    }
    Ok(())
}

#[then("an Instruction carrying the bytes fails to deserialize")]
fn instruction_with_bytes_fails_to_deserialize(
    world: &mut CucumberWorld,
    step: &Step,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let key_bytes = scenario.off_curve_bytes()?;
    if !raw_key_instruction_fails_to_decode(key_bytes, scenario.minimum_stake())? {
        return Err(StepError::AssertionFailed {
            message: "a Stake instruction carrying the off-curve bytes deserializes".to_owned(),
        });
    }
    Ok(())
}
