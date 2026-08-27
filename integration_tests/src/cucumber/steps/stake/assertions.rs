#![expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step handlers use the framework's mutable-world signature"
)]

use std::str::FromStr;

use cucumber::{Parameter, gherkin::Step, then};
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
    stake_scenario::{AccountRole, raw_key_instruction_fails_to_decode},
    world::CucumberWorld,
};

/// Comma-and-`and`-separated list of account roles as written in a feature
/// file, for example `config, funding and ownership`.
#[derive(Debug, Parameter)]
#[param(name = "account_roles", regex = r"[a-z ,]+")]
struct AccountRoles(Vec<AccountRole>);

impl FromStr for AccountRoles {
    type Err = StepError;

    fn from_str(list: &str) -> Result<Self, Self::Err> {
        list.split(',')
            .flat_map(|part| part.split(" and "))
            .map(AccountRole::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }
}

/// One side of a paired registration: the sequencer key and the accounts its
/// `Stake` names or custodies into.
struct StakeCast {
    sequencer_key: SequencerKey,
    funding_id: AccountId,
    ownership_id: AccountId,
    funds_id: AccountId,
}

/// Returns the config entry backing the scenario's sequencer key, or an
/// assertion failure if there is none.
async fn required_entry(world: &CucumberWorld) -> Result<SequencerEntry, StepError> {
    config_entry(world.lez()?, world.stake()?.sequencer_key())
        .await?
        .ok_or_else(|| StepError::AssertionFailed {
            message: "the config has no entry for the sequencer key".to_owned(),
        })
}

/// Waits for the last submission to land in a block. "Accepted" reads that
/// as the transaction taking effect; "included in a block" is the neutral
/// form for a fee-charged transaction whose execution failed, which is still
/// included with its fee kept and its effects reverted, and whose rejection
/// the steps that follow pin through the unchanged state.
#[then("the stake transaction is accepted")]
#[then("the donation transaction is accepted")]
#[then("the stake transaction is included in a block")]
async fn stake_transaction_accepted(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let hash = scenario.last_submission()?.hash;
    wait_for_inclusion(world.lez()?, hash, scenario.wait_timeout()?).await?;
    Ok(())
}

#[then(expr = "the stake transaction is not included within the next {int} blocks")]
#[then(expr = "the donation transaction is not included within the next {int} blocks")]
async fn transaction_not_included(
    world: &mut CucumberWorld,
    step: &Step,
    blocks: u64,
) -> StepResult {
    log_step(step);
    let context = world.lez()?;
    let scenario = world.stake()?;
    assert_not_included(
        context,
        scenario.last_submission()?,
        blocks,
        scenario.wait_timeout()?,
    )
    .await
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

/// Asserts that the `role` account's balance moved by exactly the amount of
/// the last submission relative to the pre-submission snapshot.
#[then(regex = "^the ([a-z ]+) account balance increased by the (?:staked|donated) amount$")]
async fn account_balance_increased(
    world: &mut CucumberWorld,
    step: &Step,
    role: AccountRole,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let account_id = scenario.account_id(role)?;
    let balance_before = scenario.snapshot()?.account(account_id)?.balance;
    let expected = balance_before
        .checked_add(scenario.last_submission()?.amount)
        .ok_or_else(|| StepError::AssertionFailed {
            message: format!("expected {role:?} balance overflows"),
        })?;
    let observed = get_account(world.lez()?, account_id).await?.balance;
    if observed != expected {
        return Err(StepError::AssertionFailed {
            message: format!("the {role:?} balance is {observed}, expected {expected}"),
        });
    }
    Ok(())
}

/// Asserts that the `role` account's balance equals its pre-submission
/// snapshot, whatever happened to its data or owner.
#[then(regex = "^the ([a-z ]+) account balance is unchanged$")]
async fn account_balance_unchanged(
    world: &mut CucumberWorld,
    step: &Step,
    role: AccountRole,
) -> StepResult {
    log_step(step);
    let scenario = world.stake()?;
    let account_id = scenario.account_id(role)?;
    let expected = scenario.snapshot()?.account(account_id)?.balance;
    let observed = get_account(world.lez()?, account_id).await?.balance;
    if observed != expected {
        return Err(StepError::AssertionFailed {
            message: format!("the {role:?} balance is {observed}, expected {expected}"),
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

#[then(expr = "the {account_roles} accounts are unchanged")]
async fn accounts_are_unchanged(
    world: &mut CucumberWorld,
    step: &Step,
    roles: AccountRoles,
) -> StepResult {
    log_step(step);
    let context = world.lez()?;
    let scenario = world.stake()?;
    let snapshot = scenario.snapshot()?;
    let current = try_join_all(roles.0.into_iter().map(|role| async move {
        let account_id = scenario.account_id(role)?;
        let before = snapshot.account(account_id)?;
        Ok::<_, StepError>((role, before, get_account(context, account_id).await?))
    }))
    .await?;
    for (role, before, after) in current {
        if after != *before {
            return Err(StepError::AssertionFailed {
                message: format!(
                    "the {role:?} account differs from its pre-submission snapshot: \
                     {before:?} -> {after:?}"
                ),
            });
        }
    }
    Ok(())
}

/// The two casts of a paired registration.
fn stake_pairs(world: &CucumberWorld) -> Result<[StakeCast; 2], StepError> {
    let scenario = world.stake()?;
    Ok([
        StakeCast {
            sequencer_key: scenario.sequencer_key(),
            funding_id: scenario.funding_id()?,
            ownership_id: scenario.ownership_id()?,
            funds_id: scenario.funds_id()?,
        },
        StakeCast {
            sequencer_key: scenario.second_sequencer_key(),
            funding_id: scenario.second_funding_id()?,
            ownership_id: scenario.second_ownership_id()?,
            funds_id: scenario.second_funds_id()?,
        },
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
    let timeout = scenario.wait_timeout()?;
    let context = world.lez()?;
    try_join_all(
        hashes
            .into_iter()
            .map(|hash| wait_for_inclusion(context, hash, timeout)),
    )
    .await?;
    Ok(())
}

#[then("the config holds an entry for each sequencer key pointing at its own ownership account")]
async fn config_holds_entry_per_key(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let amount = world.stake()?.last_submission()?.amount;
    for StakeCast {
        sequencer_key,
        ownership_id,
        ..
    } in stake_pairs(world)?
    {
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
    for StakeCast {
        sequencer_key,
        ownership_id,
        ..
    } in stake_pairs(world)?
    {
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
    let timeout = scenario.wait_timeout()?;
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
    wait_for_joint_accreditation(context, keys, atomic, timeout).await
}

#[then("each stake moved the staked amount from its funding account into its funds account")]
async fn each_stake_moved_the_amount(world: &mut CucumberWorld, step: &Step) -> StepResult {
    log_step(step);
    let amount = world.stake()?.last_submission()?.amount;
    for StakeCast {
        funding_id,
        ownership_id,
        funds_id,
        ..
    } in stake_pairs(world)?
    {
        let snapshot = world.stake()?.snapshot()?;
        let expected_funding = snapshot
            .account(funding_id)?
            .balance
            .checked_sub(amount)
            .ok_or_else(|| StepError::AssertionFailed {
                message: "expected funding balance underflows".to_owned(),
            })?;
        let expected_funds = snapshot
            .account(funds_id)?
            .balance
            .checked_add(amount)
            .ok_or_else(|| StepError::AssertionFailed {
                message: "expected funds balance overflows".to_owned(),
            })?;
        let context = world.lez()?;
        let funding = get_account(context, funding_id).await?.balance;
        let funds = get_account(context, funds_id).await?.balance;
        if funding != expected_funding || funds != expected_funds {
            return Err(StepError::AssertionFailed {
                message: format!(
                    "the stake through {ownership_id:?} left balances funding {funding} and \
                     funds {funds}, expected {expected_funding} and {expected_funds}"
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
