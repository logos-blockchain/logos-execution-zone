#![expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers use the framework's mutable-world signature"
)]

use cucumber::{gherkin::Step, then};
use futures::future::try_join_all;
use lee::{Account, AccountId};
use sequencer_stake_core::{SequencerEntry, SequencerKey, StakeRecord};

use super::{
    super::log_step,
    helpers::{
        assert_not_included, config_entry, get_account, inclusion_block, wait_for_inclusion,
        wait_for_joint_accreditation,
    },
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

/// The two `(sequencer key, funding, ownership)` casts of a paired
/// registration.
fn stake_pairs(
    world: &CucumberWorld,
) -> Result<[(SequencerKey, AccountId, AccountId); 2], StepError> {
    let scenario = world.stake()?;
    Ok([
        (
            scenario.sequencer_key(),
            scenario.funding_id()?,
            scenario.ownership_id()?,
        ),
        (
            scenario.second_sequencer_key(),
            scenario.second_funding_id()?,
            scenario.second_ownership_id()?,
        ),
    ])
}

#[then("both stake transactions are accepted")]
async fn both_stake_transactions_accepted(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let hashes = [
        scenario.last_submission()?.hash,
        scenario.second_submission()?.hash,
    ];
    let context = world.lez()?;
    try_join_all(
        hashes
            .into_iter()
            .map(|hash| wait_for_inclusion(context, hash)),
    )
    .await?;
    Ok(())
}

#[then("both stake transactions were included in the same block")]
async fn stakes_included_in_same_block(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let first_hash = scenario.last_submission()?.hash;
    let second_hash = scenario.second_submission()?.hash;
    let context = world.lez()?;
    let first_block = inclusion_block(context, first_hash).await?;
    let second_block = inclusion_block(context, second_hash).await?;
    if first_block.is_none() || first_block != second_block {
        return Err(StepError::AssertionFailed {
            message: format!(
                "the Stakes were included in blocks {first_block:?} and {second_block:?}; the \
                 shared-block-build property this scenario pins was not exercised — the \
                 back-to-back submissions raced a block boundary, so rerun the scenario"
            ),
        });
    }
    Ok(())
}

#[then("the config holds an entry for each sequencer key pointing at its own ownership account")]
async fn config_holds_entry_per_key(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let amount = world.stake()?.last_submission()?.amount;
    for (sequencer_key, _funding_id, ownership_id) in stake_pairs(world)? {
        let entry = config_entry(world.lez()?, sequencer_key)
            .await?
            .ok_or_else(|| StepError::AssertionFailed {
                message: format!("the config has no entry for sequencer key {sequencer_key:?}"),
            })?;
        if entry.account_id != ownership_id
            || entry.total_staked != amount
            || entry.total_pending_unstake != 0
        {
            return Err(StepError::AssertionFailed {
                message: format!(
                    "the entry for {sequencer_key:?} is {entry:?}, expected it to point at \
                     {ownership_id:?} tracking {amount} staked with 0 pending unstake"
                ),
            });
        }
    }
    Ok(())
}

#[then("each ownership account is claimed by sequencer_stake backing its sequencer key")]
async fn each_ownership_account_claimed(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    for (sequencer_key, _funding_id, ownership_id) in stake_pairs(world)? {
        let account = get_account(world.lez()?, ownership_id).await?;
        if account.program_owner != programs::sequencer_stake().id().into() {
            return Err(StepError::AssertionFailed {
                message: format!(
                    "ownership account {ownership_id:?} is not owned by sequencer_stake"
                ),
            });
        }
        let record = StakeRecord::from_bytes(account.data.as_ref()).ok_or_else(|| {
            StepError::AssertionFailed {
                message: format!(
                    "ownership account {ownership_id:?} data does not decode as a StakeRecord"
                ),
            }
        })?;
        if record.sequencer_key != sequencer_key || record.pending_unstake.is_some() {
            return Err(StepError::AssertionFailed {
                message: format!(
                    "ownership account {ownership_id:?} carries {record:?}, expected its own \
                     sequencer key with no pending unstake"
                ),
            });
        }
    }
    Ok(())
}

#[then("both sequencer keys join the live committee together")]
async fn both_keys_join_live_committee(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let first_hash = scenario.last_submission()?.hash;
    let second_hash = scenario.second_submission()?.hash;
    let keys = [
        scenario.sequencer_key().to_bytes(),
        scenario.second_sequencer_key().to_bytes(),
    ];
    let context = world.lez()?;

    // Stakes sharing a block finalize together, so the joint-accreditation
    // wait may insist on one atomic committee update. In the rare race where
    // the two Stakes land in different blocks, split updates are legitimate
    // and only the eventual outcome is asserted.
    let first_block = inclusion_block(context, first_hash).await?;
    let second_block = inclusion_block(context, second_hash).await?;
    let atomic = first_block.is_some() && first_block == second_block;
    tracing::info!(
        target: super::super::TARGET,
        "Stakes included in blocks {first_block:?} and {second_block:?}: {}",
        if atomic {
            "insisting on one atomic committee update"
        } else {
            "split blocks, asserting only the eventual outcome"
        }
    );
    wait_for_joint_accreditation(context, keys, atomic).await
}

#[then("each stake moved the staked amount from its funding account to its ownership account")]
async fn each_stake_moved_the_amount(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let amount = world.stake()?.last_submission()?.amount;
    for (_sequencer_key, funding_id, ownership_id) in stake_pairs(world)? {
        let snapshot = world.stake()?.snapshot()?;
        let expected_funding = snapshot
            .account(funding_id)?
            .balance
            .checked_sub(amount)
            .ok_or_else(|| StepError::AssertionFailed {
                message: "expected funding balance underflows".to_owned(),
            })?;
        let expected_ownership = snapshot
            .account(ownership_id)?
            .balance
            .checked_add(amount)
            .ok_or_else(|| StepError::AssertionFailed {
                message: "expected ownership balance overflows".to_owned(),
            })?;
        let context = world.lez()?;
        let funding = get_account(context, funding_id).await?.balance;
        let ownership = get_account(context, ownership_id).await?.balance;
        if funding != expected_funding || ownership != expected_ownership {
            return Err(StepError::AssertionFailed {
                message: format!(
                    "the stake through {ownership_id:?} left balances funding {funding} and \
                     ownership {ownership}, expected {expected_funding} and {expected_ownership}"
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
