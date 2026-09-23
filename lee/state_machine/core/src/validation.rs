//! The one execution-validation traversal, shared by the sequencer and the zkVM guest.
//!
//! Check order is contract: callers discriminate on which error surfaces first.

use std::collections::{HashMap, HashSet, VecDeque, hash_map::Entry};

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
    pub pda_seeds: &'call [PdaSeed],
    /// Inherited, before this call's output extends it. Empty at the root, where an external
    /// root authority holds the set itself.
    pub authorized_accounts: &'call HashSet<AccountId>,
}

pub enum AccountSource {
    Authoritative(AccountData),
    /// No view of its own: each shard's claim is adopted the first time it is named.
    AdoptClaims,
}

pub struct TrackedAccount {
    pub current: AccountData,
    /// The adopted claims, for an account that adopts them. Keeps empty shards: a named empty
    /// shard differs from an unnamed one.
    pub claimed_initial: Option<AccountData>,
    pub exported_authorization: bool,
}

pub struct ThreadedDiff {
    pub accounts: HashMap<AccountId, TrackedAccount>,
    /// The accounts that adopt claims, in first-sight order.
    pub claim_order: Vec<AccountId>,
}

pub trait Backend {
    type Error: From<ValidationError>;

    /// Runs once per call, before every other hook, so it may set per-call scratch. `accounts`
    /// holds every earlier call's result, so it is read before chain state.
    fn output_for_call(
        &mut self,
        call: &ChainedCall,
        ctx: &CallContext<'_>,
        accounts: &HashMap<AccountId, TrackedAccount>,
    ) -> Result<ProgramOutput, Self::Error>;

    /// Asked once per account, at its first sight: adoption is sound only because the source is
    /// a property of the environment, not the moment.
    fn account_source(&self, account_id: AccountId) -> AccountSource;

    /// Judge one journalled `is_authorized` claim and return the value to export; `prior_export`
    /// is what the account's first sight exported, `None` at first sight. The journalled flag,
    /// not the export, extends the subtree set. An export may mask that flag but never exceed
    /// it, because it is also what the account's later sightings are judged against.
    fn judge_authorization(
        &mut self,
        pre: &AccountInput,
        prior_export: Option<bool>,
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
    let mut accounts: HashMap<AccountId, TrackedAccount> = HashMap::new();
    let mut claim_order: Vec<AccountId> = Vec::new();
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
            pda_seeds: &chained_call.pda_seeds,
            authorized_accounts: &caller_authorized,
        };

        let program_output = backend.output_for_call(&chained_call, &ctx, &accounts)?;

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

            let (account, prior_export) = match accounts.entry(account_id) {
                Entry::Occupied(entry) => {
                    let account = entry.into_mut();
                    let prior_export = Some(account.exported_authorization);
                    (account, prior_export)
                }
                Entry::Vacant(entry) => {
                    let (current, claimed_initial) = match backend.account_source(account_id) {
                        AccountSource::Authoritative(data) => (data, None),
                        AccountSource::AdoptClaims => {
                            claim_order.push(account_id);
                            (AccountData::default(), Some(AccountData::default()))
                        }
                    };
                    let account = entry.insert(TrackedAccount {
                        current,
                        claimed_initial,
                        exported_authorization: false,
                    });
                    (account, None)
                }
            };

            let (program, data) = &pre.shard;
            if selectors_seen.insert(shard_selector)
                && let Some(claimed_initial) = &mut account.claimed_initial
            {
                // `insert`, not `set_shard`: an empty adopted shard must stay recorded.
                claimed_initial.shards.insert(*program, data.clone());
                account.current.set_shard(*program, data.clone());
            }
            if account.current.shard(*program) != data {
                return Err(ValidationError::ProgramBehavior(
                    InvalidProgramBehaviorError::InconsistentAccountPreState {
                        account_id,
                        expected: Box::new(AccountInput::at(
                            shard_selector,
                            pre.is_authorized,
                            &account.current,
                        )),
                        actual: Box::new(pre.clone()),
                    },
                )
                .into());
            }

            if pre.is_authorized {
                journalled_authorized.push(account_id);
            }

            let exported = backend.judge_authorization(pre, prior_export, &ctx)?;
            if prior_export.is_none() {
                account.exported_authorization = exported;
            }
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
            accounts
                .get_mut(&diff.pre_state.account_id)
                .expect("the pre-state loop tracks every account a row names")
                .current
                .apply_diff(diff);
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
        accounts,
        claim_order,
    })
}

#[cfg(test)]
mod tests;
