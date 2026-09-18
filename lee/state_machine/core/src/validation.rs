//! The one execution-validation traversal, shared by every environment that runs it.
//!
//! A transaction's call tree is walked identically whether the walk happens in the sequencer
//! (which executes each program) or inside a zkVM guest (which verifies a proof of each
//! program's execution instead). Only three things genuinely differ: where a callee's
//! [`ProgramOutput`] comes from, what an account's authoritative pre-state value is, and how a
//! PDA seed proves authorization. Those are the [`Backend`] methods; everything else lives here
//! once.
//!
//! The order of the checks below is part of the contract, not an implementation detail: callers
//! discriminate on which error surfaces first, and in the public environment that choice decides
//! whether a failing transaction is charged and reverted or rejects the block.

use std::collections::{HashMap, HashSet, VecDeque};

use thiserror::Error;

use crate::{
    account::{Account, AccountId, AccountWithMetadata},
    error::InvalidProgramBehaviorError,
    program::{
        AccountStateDiff, BlockValidityWindow, CallKind, ChainedCall, DEFAULT_PROGRAM_OWNER,
        MAX_NUMBER_CHAINED_CALLS, PdaSeed, ProgramEvent, ProgramOutput, TimestampValidityWindow,
        is_ownership_settled, post_state, pre_states_match_accounts, validate_execution,
    },
};

/// The rejections the shared traversal itself owns. Everything else a backend rejects on is its
/// own error type, reached through [`Backend::Error`].
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error(transparent)]
    ProgramBehavior(#[from] InvalidProgramBehaviorError),

    #[error("Chain of calls is too long")]
    MaxChainedCallsDepthExceeded,
}

/// What the traversal already knows about the call in flight, so no backend recomputes it.
pub struct CallContext<'call> {
    /// The invoking program's account, or `None` at the top-level call. Also the backends'
    /// "is this the root" signal.
    pub caller_account_id: Option<AccountId>,
    /// The callee's own dispatch address.
    pub program_account_id: AccountId,
    /// Seeds the caller delegated to this call.
    pub pda_seeds: &'call [PdaSeed],
    /// The subtree-scoped authorized set this call inherited, before its own output extends it.
    /// Empty at the root: an environment whose root authority is external, such as a signature,
    /// holds that set itself and unions it in [`Backend::judge_authorization`].
    pub authorized_accounts: &'call HashSet<AccountId>,
    /// Every account written so far in this transaction, keyed by id. A backend that resolves
    /// pre-states or loads programs from chain state reads this first, so an account an earlier
    /// call in the same transaction wrote is seen immediately.
    pub touched: &'call HashMap<AccountId, Account>,
}

/// Transaction-level declarations the traversal enforces.
pub struct Declarations<'tx> {
    /// Accounts that must appear somewhere in the final state. A program cannot silently drop an
    /// account the transaction was invoked with.
    pub must_be_touched: &'tx [AccountId],
    /// Whether the top-level call's own output is confined to the ids its call named. Chained
    /// calls are always confined, by the stronger ordered check `pre_states_match_accounts`; the
    /// root has a caller-supplied declaration to confine it only in some environments.
    pub root_output_is_confined: bool,
}

/// The transaction's effect: every account it touched, in first-sight order, paired with its
/// final state.
///
/// First-sight order is load-bearing for environments that index per-account witness data
/// positionally, so it must not be reordered or deduplicated downstream.
pub struct ThreadedDiff {
    pub accounts: Vec<(AccountWithMetadata, Account)>,
}

/// The environment a traversal runs in.
pub trait Backend {
    type Error: From<ValidationError>;

    /// Produce the output for `call`.
    ///
    /// Called exactly once per call and before every other hook, so an implementation may use it
    /// for per-call scratch. An environment that executes programs runs the program here; one
    /// that verifies proofs checks the prover's supplied output against its receipt here.
    fn output_for_call(
        &mut self,
        call: &ChainedCall,
        ctx: &CallContext<'_>,
    ) -> Result<ProgramOutput, Self::Error>;

    /// The value `account_id` is independently known to hold, the first time this transaction
    /// sees it.
    ///
    /// `None` means there is no independently known value and the journalled claim stands,
    /// because it is bound by something outside this traversal.
    fn expected_first_sight(
        &mut self,
        account_id: AccountId,
        ctx: &CallContext<'_>,
    ) -> Result<Option<Account>, Self::Error>;

    /// Judge one journalled pre-state's `is_authorized` claim, and return the value to export
    /// for it.
    ///
    /// `position` is the account's index in first-sight order and `first_sight` is true on its
    /// first appearance anywhere in the call tree. Returning anything other than
    /// `pre.is_authorized` means this environment exports a different view of authorization than
    /// the one the callee ran under; that value reaches only [`ThreadedDiff`]. The journalled
    /// flag is what extends the subtree's authorized set and what `validate_execution` judges,
    /// so a divergent export can never widen what a program was allowed to do.
    fn judge_authorization(
        &mut self,
        pre: &AccountWithMetadata,
        position: usize,
        first_sight: bool,
        ctx: &CallContext<'_>,
    ) -> Result<bool, Self::Error>;

    /// Resolve one write's `post_data`, in whatever way this environment does that. Called once
    /// per diff, write or read, before `validate_execution` and post-state materialization see
    /// it - both run against the resolved diff, not the one `output_for_call` returned. Called
    /// for reads too so an environment can observe them, not just resolve writes.
    ///
    /// The default is a verbatim pass-through: an environment with nothing further to resolve a
    /// write against, and nothing to observe in a read, just keeps what the call already
    /// produced.
    fn resolve_write(
        &mut self,
        diff: &AccountStateDiff,
        _ctx: &CallContext<'_>,
    ) -> Result<AccountStateDiff, Self::Error> {
        Ok(diff.clone())
    }

    /// One call's declared validity windows, in traversal order.
    fn observe_windows(
        &mut self,
        block: BlockValidityWindow,
        timestamp: TimestampValidityWindow,
    ) -> Result<(), Self::Error>;

    /// One call's emitted events. Dropped by default.
    fn observe_events(&mut self, _emitter: AccountId, _events: Vec<ProgramEvent>) {}

    /// Last word, after the traversal's own end-of-transaction rules.
    fn finish(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Walk the call tree rooted at `initial_call`, validating every call against the rules both
/// environments share and deferring to `backend` for the rest.
///
/// Calls are visited depth-first in declaration order: a call's own chained calls run, in order,
/// before its next sibling.
pub fn validate_state_diff<B: Backend>(
    backend: &mut B,
    initial_call: ChainedCall,
    declarations: &Declarations<'_>,
) -> Result<ThreadedDiff, B::Error> {
    let mut touched: HashMap<AccountId, Account> = HashMap::new();
    let mut first_sight: Vec<AccountWithMetadata> = Vec::new();
    let mut position_of: HashMap<AccountId, usize> = HashMap::new();

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

        // The callee must have run the instruction its caller asked for. An environment that
        // executes the program gets this for free; one that verifies a prover-chosen proof of it
        // does not, and without this a caller's chained call could be answered by a proof of the
        // same program run on a different instruction entirely.
        if program_output.instruction_data != chained_call.instruction_data {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::MismatchedInstructionData {
                    program_account_id: chained_call.program_account_id,
                },
            )
            .into());
        }

        // A chained callee must account for exactly the accounts its caller named, in order. The
        // top-level call has no caller, so it is exempt.
        if caller_account_id.is_some()
            && !pre_states_match_accounts(
                &chained_call.pre_state_ids,
                &program_output
                    .state_diffs
                    .iter()
                    .map(|diff| diff.pre_state.clone())
                    .collect::<Vec<_>>(),
            )
        {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::ChainedCallAccountsMismatch {
                    program_account_id: chained_call.program_account_id,
                },
            )
            .into());
        }

        // Journalled authorization, captured before any backend rewrite, is what extends the
        // subtree's authorized set below.
        let mut journalled_authorized: Vec<AccountId> = Vec::new();
        let confined = caller_account_id.is_some() || declarations.root_output_is_confined;
        let named_accounts: HashSet<AccountId> =
            chained_call.pre_state_ids.iter().copied().collect();

        for diff in &program_output.state_diffs {
            let pre = &diff.pre_state;
            let account_id = pre.account_id;

            if confined && !named_accounts.contains(&account_id) {
                return Err(ValidationError::ProgramBehavior(
                    InvalidProgramBehaviorError::UndeclaredAccountInProgramOutput {
                        program_account_id: chained_call.program_account_id,
                        account_id,
                    },
                )
                .into());
            }

            // The journalled pre-state must match whatever the environment independently tracks:
            // an earlier call's post-state if there is one, otherwise the backend's own view.
            //
            // First sight is keyed on the position map rather than on `touched`, which this call
            // does not update until its whole pre loop has run: an output naming one account
            // twice must not claim two positions. `validate_execution` rejects it either way.
            let seen_before = position_of.contains_key(&account_id);
            let expected = match touched.get(&account_id) {
                Some(account) => Some(account.clone()),
                None if !seen_before => backend.expected_first_sight(account_id, &ctx)?,
                None => None,
            };
            if let Some(expected) = expected
                && pre.account != expected
            {
                return Err(ValidationError::ProgramBehavior(
                    InvalidProgramBehaviorError::InconsistentAccountPreState {
                        account_id,
                        expected: Box::new(expected),
                        actual: Box::new(pre.account.clone()),
                    },
                )
                .into());
            }

            if pre.is_authorized {
                journalled_authorized.push(account_id);
            }

            let position = if seen_before {
                *position_of
                    .get(&account_id)
                    .expect("seen_before is read from this very map")
            } else {
                first_sight.len()
            };
            let exported = backend.judge_authorization(pre, position, !seen_before, &ctx)?;

            if !seen_before {
                position_of.insert(account_id, position);
                first_sight.push(AccountWithMetadata {
                    is_authorized: exported,
                    ..pre.clone()
                });
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

        // Without this a program could privately invoke its own internal entry points by
        // claiming to be its own caller, bypassing access control.
        if program_output.caller_account_id != caller_account_id {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::MismatchedCallerProgramId {
                    expected: caller_account_id,
                    actual: program_output.caller_account_id,
                },
            )
            .into());
        }

        // Only a top-level call may legitimately be a no-op; a chained call must execute.
        if caller_account_id.is_some() && program_output.call_kind != CallKind::Execute {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::ChainedCallDidNotExecute {
                    program_account_id: chained_call.program_account_id,
                },
            )
            .into());
        }

        // Resolved once here, so `validate_execution` and post-state materialization below both
        // see what a write's `post_data` actually resolves to, not the delta `output_for_call`
        // produced. Called for every diff, including reads, so a backend can observe those too.
        let resolved_diffs: Vec<AccountStateDiff> = program_output
            .state_diffs
            .iter()
            .map(|diff| backend.resolve_write(diff, &ctx))
            .collect::<Result<Vec<_>, _>>()?;

        validate_execution(&resolved_diffs, chained_call.program_account_id).map_err(|err| {
            ValidationError::ProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
                err,
            ))
        })?;

        backend.observe_windows(
            program_output.block_validity_window,
            program_output.timestamp_validity_window,
        )?;

        // Materialize post-states, acquiring ownership of every unowned account this call wrote
        // data to. Deferred until the whole pre loop has run so `CallContext` can borrow
        // `touched`; unobservable, because `validate_execution` already rejects an output naming
        // the same account twice.
        for diff in &resolved_diffs {
            let post = post_state(diff, chained_call.program_account_id).map_err(|err| {
                ValidationError::ProgramBehavior(InvalidProgramBehaviorError::BalanceDiffFailed(
                    err,
                ))
            })?;
            touched.insert(diff.pre_state.account_id, post);
        }

        backend.observe_events(chained_call.program_account_id, program_output.events);

        // Sourced from the callee's own journalled echo, which the loop above already gated,
        // rather than from the bare ids its caller supplied, which carry no authorization claim
        // and are forgeable (audit issue 91).
        //
        // Authorization grows monotonically down a branch: once authorized it stays authorized
        // for that call's descendants. Siblings are unaffected, each child gets its own clone.
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

    let accounts: Vec<(AccountWithMetadata, Account)> = first_sight
        .into_iter()
        .map(|pre| {
            let post = touched
                .get(&pre.account_id)
                .cloned()
                .expect("every pre-state gets a post-state in the same call");
            (pre, post)
        })
        .collect();

    // Every account that entered the transaction unowned and changed must have been claimed by
    // whichever program wrote to it.
    for (pre, post) in &accounts {
        if pre.account.program_owner == DEFAULT_PROGRAM_OWNER
            && pre.account != *post
            && !is_ownership_settled(post)
        {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::DataBearingUnownedAccount {
                    account_id: pre.account_id,
                },
            )
            .into());
        }
    }

    for account_id in declarations.must_be_touched {
        if !touched.contains_key(account_id) {
            return Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::DeclaredAccountMissingFromOutput {
                    account_id: *account_id,
                },
            )
            .into());
        }
    }

    backend.finish()?;

    Ok(ThreadedDiff { accounts })
}

#[cfg(test)]
mod tests;
