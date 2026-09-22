//! The one execution-validation traversal, shared by the sequencer and the zkVM guest.
//!
//! Check order is contract: callers discriminate on which error surfaces first.

use std::collections::{HashMap, HashSet, VecDeque};

use thiserror::Error;

use crate::{
    account::{AccountData, AccountId, ProgramShardSelector},
    error::InvalidProgramBehaviorError,
    program::{
        AccountInput, BlockValidityWindow, CallKind, ChainedCall, MAX_NUMBER_CHAINED_CALLS,
        PdaSeed, ProgramEvent, ProgramOutput, TimestampValidityWindow,
        pre_states_match_shard_selectors, validate_execution,
    },
};

/// Rejections the traversal itself owns; the rest live in [`Backend::Error`].
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error(transparent)]
    ProgramBehavior(#[from] InvalidProgramBehaviorError),

    #[error("Chain of calls is too long")]
    MaxChainedCallsDepthExceeded,
}

pub struct CallContext<'call> {
    pub caller_account_id: Option<AccountId>,
    pub program_account_id: AccountId,
    pub pda_seeds: &'call [PdaSeed],
    /// Inherited, before this call's output extends it. Empty at the root, where an external
    /// root authority holds the set itself.
    pub authorized_accounts: &'call HashSet<AccountId>,
    /// Every account written so far. A backend resolving values or programs reads this before
    /// chain state, so an earlier call's result is seen immediately.
    pub touched: &'call HashMap<AccountId, AccountData>,
}

pub struct ThreadedDiff {
    pub touched: HashMap<AccountId, AccountData>,
    pub first_sight: Vec<(AccountId, bool)>,
    pub at_first_sight: HashMap<AccountId, AccountData>,
}

pub trait Backend {
    type Error: From<ValidationError>;

    /// Runs once per call, before every other hook, so it may set per-call scratch.
    fn output_for_call(
        &mut self,
        call: &ChainedCall,
        ctx: &CallContext<'_>,
    ) -> Result<ProgramOutput, Self::Error>;

    /// Whether this environment has its own view of `account_id`. `false` adopts each shard's
    /// claim the first time it is named. Must answer the same for an account throughout:
    /// adoption is sound only because this is a property of the environment, not the moment.
    fn has_independent_view(&mut self, account_id: AccountId) -> bool;

    /// The account's state at first sight. Called once per account.
    fn value_at_first_sight(
        &mut self,
        account_id: AccountId,
        ctx: &CallContext<'_>,
    ) -> Result<Option<AccountData>, Self::Error>;

    /// Judge one journalled `is_authorized` claim and return the value to export. An export
    /// that differs from `pre.is_authorized` reaches only [`ThreadedDiff`]: the journalled flag
    /// is what extends the subtree set and what `validate_execution` judges, so a divergent
    /// export can never widen what a program was allowed to do.
    fn judge_authorization(
        &mut self,
        pre: &AccountInput,
        first_sight: bool,
        ctx: &CallContext<'_>,
    ) -> Result<bool, Self::Error>;

    fn observe_windows(
        &mut self,
        block: BlockValidityWindow,
        timestamp: TimestampValidityWindow,
    ) -> Result<(), Self::Error>;

    fn observe_events(&mut self, _emitter: AccountId, _events: Vec<ProgramEvent>) {}

    fn finish(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Walk the call tree rooted at `initial_call`, deferring to `backend` for what differs.
/// Depth-first in declaration order: a call's own chained calls run before its next sibling.
pub fn validate_state_diff<B: Backend>(
    backend: &mut B,
    initial_call: ChainedCall,
    declared: &[ProgramShardSelector],
) -> Result<ThreadedDiff, B::Error> {
    let mut touched: HashMap<AccountId, AccountData> = HashMap::new();
    let mut first_sight: Vec<(AccountId, bool)> = Vec::new();
    let mut at_first_sight: HashMap<AccountId, AccountData> = HashMap::new();
    let mut selectors_seen: HashSet<ProgramShardSelector> = HashSet::new();

    let mut chained_calls = VecDeque::from_iter([(initial_call, None, HashSet::new())]);
    let mut chain_calls_counter: usize = 0;

    while let Some((chained_call, caller_account_id, caller_authorized)) = chained_calls.pop_front()
    {
        if chain_calls_counter > MAX_NUMBER_CHAINED_CALLS {
            return Err(ValidationError::MaxChainedCallsDepthExceeded.into());
        }

        let ctx = CallContext {
            caller_account_id,
            program_account_id: chained_call.program_account_id,
            pda_seeds: &chained_call.pda_seeds,
            authorized_accounts: &caller_authorized,
            touched: &touched,
        };

        let program_output = backend.output_for_call(&chained_call, &ctx)?;

        // Free where the program is executed; an environment verifying a prover-chosen proof
        // could otherwise answer with a proof of a different instruction.
        if program_output.instruction_data != chained_call.instruction_data {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::MismatchedInstructionData {
                    program_account_id: chained_call.program_account_id,
                },
            )
            .into());
        }

        // A chained callee echoes its caller's selectors exactly; the root has no caller.
        if caller_account_id.is_some()
            && !pre_states_match_shard_selectors(
                &chained_call.shard_selectors,
                &program_output.state_diffs,
            )
        {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::ChainedCallAccountsMismatch {
                    program_account_id: chained_call.program_account_id,
                },
            )
            .into());
        }

        let named_accounts: HashSet<AccountId> = chained_call
            .shard_selectors
            .iter()
            .map(|shard_selector| shard_selector.account_id)
            .collect();

        // Captured before any backend rewrite: this is what extends the subtree set.
        let mut journalled_authorized: Vec<AccountId> = Vec::new();

        for diff in &program_output.state_diffs {
            let pre = &diff.pre_state;
            let account_id = pre.account_id;
            let shard_selector = ProgramShardSelector::from(pre);

            // Only a call that declares nothing may report unnamed accounts: the circuit's root.
            let confined = !named_accounts.is_empty();
            if confined && !named_accounts.contains(&account_id) {
                return Err(ValidationError::ProgramBehavior(
                    InvalidProgramBehaviorError::UndeclaredAccountInProgramOutput {
                        program_account_id: chained_call.program_account_id,
                        account_id,
                    },
                )
                .into());
            }

            // Keyed on the pre view: `touched` is not updated until this call's loop ends.
            let seen_before = at_first_sight.contains_key(&account_id);

            let adopts_claims = !backend.has_independent_view(account_id);
            let new_selector = !selectors_seen.contains(&shard_selector);

            let first_sight_value = if seen_before {
                None
            } else {
                backend.value_at_first_sight(account_id, &ctx)?
            };
            let pre_view = at_first_sight.entry(account_id).or_insert_with(|| {
                first_sight_value.unwrap_or_else(|| AccountData {
                    balance: pre.balance,
                    ..AccountData::default()
                })
            });
            let mut base = touched
                .get(&account_id)
                .cloned()
                .unwrap_or_else(|| pre_view.clone());

            if adopts_claims
                && new_selector
                && let Some((program, data)) = &pre.shard
            {
                // `insert`, not `set_shard`: an empty resolved shard must stay recorded.
                pre_view.shards.insert(*program, data.clone());
                base.set_shard(*program, data.clone());
            }
            let base = &base;
            let consistent = base.balance == pre.balance
                && pre
                    .shard
                    .as_ref()
                    .is_none_or(|(program, data)| base.shard(*program) == data);
            if !consistent {
                return Err(ValidationError::ProgramBehavior(
                    InvalidProgramBehaviorError::InconsistentAccountPreState {
                        account_id,
                        expected: Box::new(AccountInput::at(
                            shard_selector,
                            pre.is_authorized,
                            base,
                        )),
                        actual: Box::new(pre.clone()),
                    },
                )
                .into());
            }

            if pre.is_authorized {
                journalled_authorized.push(account_id);
            }

            let exported = backend.judge_authorization(pre, !seen_before, &ctx)?;
            if !seen_before {
                first_sight.push((account_id, exported));
            }

            selectors_seen.insert(shard_selector);
        }

        if program_output.self_account_id != chained_call.program_account_id {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::MismatchedProgramId {
                    expected: chained_call.program_account_id,
                    actual: program_output.self_account_id,
                },
            )
            .into());
        }

        // Else a program could reach its own internal entry points by claiming to be its caller.
        if program_output.caller_account_id != caller_account_id {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::MismatchedCallerProgramId {
                    expected: caller_account_id,
                    actual: program_output.caller_account_id,
                },
            )
            .into());
        }

        if caller_account_id.is_some() && program_output.call_kind != CallKind::Execute {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::ChainedCallDidNotExecute {
                    program_account_id: chained_call.program_account_id,
                },
            )
            .into());
        }

        validate_execution(&program_output.state_diffs, chained_call.program_account_id).map_err(
            |err| {
                ValidationError::ProgramBehavior(
                    InvalidProgramBehaviorError::ExecutionValidationFailed(err),
                )
            },
        )?;

        backend.observe_windows(
            program_output.block_validity_window,
            program_output.timestamp_validity_window,
        )?;

        for diff in &program_output.state_diffs {
            let account_id = diff.pre_state.account_id;
            let mut data = touched
                .remove(&account_id)
                .or_else(|| at_first_sight.get(&account_id).cloned())
                .unwrap_or_else(|| data_of(&diff.pre_state));
            data.apply_diff(diff).map_err(|err| {
                ValidationError::ProgramBehavior(InvalidProgramBehaviorError::BalanceDiffFailed(
                    err,
                ))
            })?;
            touched.insert(account_id, data);
        }

        backend.observe_events(chained_call.program_account_id, program_output.events);

        // From the callee's own gated journal, not the caller's bare selectors, which carry no
        // authorization claim and are forgeable (audit issue 91). Grows monotonically down a
        // branch; siblings are unaffected, each child gets its own clone.
        let mut authorized_accounts = caller_authorized;
        authorized_accounts.extend(journalled_authorized);
        for new_call in program_output.chained_calls.into_iter().rev() {
            chained_calls.push_front((
                new_call,
                Some(chained_call.program_account_id),
                authorized_accounts.clone(),
            ));
        }

        chain_calls_counter = chain_calls_counter
            .checked_add(1)
            .expect("the max depth is checked at the top of the loop");
    }

    // A program cannot silently drop a shard it was invoked with.
    for shard_selector in declared {
        if !selectors_seen.contains(shard_selector) {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::DeclaredAccountMissingFromOutput {
                    account_id: shard_selector.account_id,
                },
            )
            .into());
        }
    }

    backend.finish()?;

    Ok(ThreadedDiff {
        touched,
        first_sight,
        at_first_sight,
    })
}

/// The `AccountData` an input describes. Used only where the environment has no view.
fn data_of(pre: &AccountInput) -> AccountData {
    let mut data = AccountData {
        balance: pre.balance,
        ..AccountData::default()
    };
    if let Some((program, shard)) = &pre.shard {
        data.set_shard(*program, shard.clone());
    }
    data
}

#[cfg(test)]
mod tests;
