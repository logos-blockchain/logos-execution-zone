//! The one execution-validation traversal, shared by every environment that runs it.
//!
//! A transaction's call tree is walked identically whether the walk happens in the sequencer
//! (which executes each program) or inside a zkVM guest (which verifies a proof of each
//! program's execution instead). Only three things genuinely differ: where a callee's
//! [`ProgramOutput`] comes from, what an account's authoritative value is, and how a PDA seed
//! proves authorization. Those are the [`Backend`] methods; everything else lives here once.
//!
//! The order of the checks below is part of the contract, not an implementation detail: callers
//! discriminate on which error surfaces first, and in the public environment that choice decides
//! whether a failing transaction is charged and reverted or rejects the block.

use std::collections::{HashMap, HashSet, VecDeque};

use thiserror::Error;

use crate::{
    account::{AccountData, AccountId, ProgramShardSelector, ShardData},
    error::InvalidProgramBehaviorError,
    program::{
        AccountInput, BlockValidityWindow, CallKind, ChainedCall, MAX_NUMBER_CHAINED_CALLS,
        PdaSeed, ProgramEvent, ProgramOutput, TimestampValidityWindow,
        pre_states_match_shard_selectors, validate_execution,
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
    /// Every account written so far in this transaction. A backend that resolves values or loads
    /// programs from chain state reads this first, so an account an earlier call in the same
    /// transaction wrote is seen immediately.
    pub touched: &'call HashMap<AccountId, AccountData>,
}

/// The transaction's effect.
pub struct ThreadedDiff {
    /// Final state of every account the transaction touched.
    pub touched: HashMap<AccountId, AccountData>,
    /// Accounts in the order the transaction first saw them, each with the authorization flag
    /// this environment chose to export, which may differ from the journalled one.
    pub first_sight: Vec<(AccountId, bool)>,
    /// Each account's state as first observed, accumulated shard by shard and never overwritten
    /// by a later post-state. This is what an environment journals for accounts it must expose.
    pub at_first_sight: HashMap<AccountId, AccountData>,
}

/// The environment a traversal runs in.
pub trait Backend {
    type Error: From<ValidationError>;

    /// Produce the output for `call`. Runs once per call, before every other hook, so an
    /// implementation may use it for per-call scratch.
    fn output_for_call(
        &mut self,
        call: &ChainedCall,
        ctx: &CallContext<'_>,
    ) -> Result<ProgramOutput, Self::Error>;

    /// The environment's own view of `account_id`, independent of anything the program claims.
    ///
    /// `None` means this environment has no independent view at all, so a journalled claim is
    /// adopted the first time each shard is seen and only cross-checked afterwards. That is the
    /// circuit, where a note's content is bound by its commitment and nullifier rather than by
    /// this traversal. An environment that answers `Some` is checked against it every time.
    fn authoritative_value(
        &mut self,
        account_id: AccountId,
        ctx: &CallContext<'_>,
    ) -> Result<Option<AccountData>, Self::Error>;

    /// Judge one journalled pre-state's `is_authorized` claim, and return the value to export.
    ///
    /// Returning anything other than `pre.is_authorized` means this environment exports a
    /// different view than the one the callee ran under; that value reaches only
    /// [`ThreadedDiff`]. The journalled flag is what extends the subtree's authorized set and
    /// what `validate_execution` judges, so a divergent export can never widen what a program
    /// was allowed to do.
    fn judge_authorization(
        &mut self,
        pre: &AccountInput,
        first_sight: bool,
        ctx: &CallContext<'_>,
    ) -> Result<bool, Self::Error>;

    /// One call's declared validity windows.
    fn observe_windows(
        &mut self,
        block: BlockValidityWindow,
        timestamp: TimestampValidityWindow,
    ) -> Result<(), Self::Error>;

    /// One call's emitted events.
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
    declared: &[ProgramShardSelector],
) -> Result<ThreadedDiff, B::Error> {
    let mut touched: HashMap<AccountId, AccountData> = HashMap::new();
    let mut first_sight: Vec<(AccountId, bool)> = Vec::new();
    // An account's full state at first sight, so shards this transaction never names survive.
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

        // A chained callee must account for exactly the shard selectors its caller named, in
        // order. The top-level call has no caller, so it is exempt.
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

        // Journalled authorization, captured before any backend rewrite, is what extends the
        // subtree's authorized set below.
        let mut journalled_authorized: Vec<AccountId> = Vec::new();
        // Shards adopted this call, applied to the running state once its borrow ends.
        let mut adopted: Vec<(AccountId, AccountId, ShardData)> = Vec::new();

        for diff in &program_output.state_diffs {
            let pre = &diff.pre_state;
            let account_id = pre.account_id;
            let shard_selector = ProgramShardSelector::from(pre);

            // A call that names no selectors constrains nothing: that is the circuit's top-level
            // call, reached through a proof rather than through a caller that named its shards.
            // The public root always names its accounts, so this never loosens it.
            if !named_accounts.is_empty() && !named_accounts.contains(&account_id) {
                return Err(ValidationError::ProgramBehavior(
                    InvalidProgramBehaviorError::UndeclaredAccountInProgramOutput {
                        program_account_id: chained_call.program_account_id,
                        account_id,
                    },
                )
                .into());
            }

            // Keyed on the pre view rather than on `touched`, which this call does not update
            // until its whole pre loop has run.
            let seen_before = at_first_sight.contains_key(&account_id);

            // What the environment independently knows about this account. `None` means it has
            // no independent view, so each shard's claim is adopted the first time it is named
            // and cross-checked on every sighting after that.
            let authoritative = backend.authoritative_value(account_id, &ctx)?;
            let adopts_claims = authoritative.is_none();
            let new_selector = !selectors_seen.contains(&shard_selector);

            // The pre view, accumulated shard by shard and never overwritten by a post-state:
            // this is what an environment journals for the accounts it must expose.
            let pre_view = at_first_sight.entry(account_id).or_insert_with(|| {
                authoritative.clone().unwrap_or_else(|| AccountData {
                    balance: pre.balance,
                    ..AccountData::default()
                })
            });
            // Compare against the current tracked value: an earlier call's result if there is
            // one, otherwise the pre view just established.
            let mut base = touched
                .get(&account_id)
                .cloned()
                .unwrap_or_else(|| pre_view.clone());

            // A shard this environment has no view of is adopted the first time it is named,
            // into the pre view the journal exposes and into the running state alike, since
            // nothing held here could contradict the claim yet.
            if adopts_claims
                && new_selector
                && let Some((program, data)) = &pre.shard
            {
                // Insert rather than `set_shard`: a resolver may legitimately answer with an
                // empty shard, and the pre view must still record that this transaction named
                // it, or the journal would drop it and the post would not line up.
                pre_view.shards.insert(*program, data.clone());
                base.set_shard(*program, data.clone());
                adopted.push((account_id, *program, data.clone()));
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

        for (account_id, program, data) in adopted {
            if let Some(tracked) = touched.get_mut(&account_id) {
                tracked.set_shard(program, data);
            }
        }

        // Apply balance and shard changes, preserving every other shard. Deferred until the whole
        // pre loop has run so `CallContext` can borrow `touched`; unobservable, because
        // `validate_execution` already rejects an output naming the same account twice.
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

        // Sourced from the callee's own journalled echo, which the loop above already gated,
        // rather than from the bare selectors its caller supplied, which carry no authorization
        // claim and are forgeable (audit issue 91).
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

    // Nothing the transaction declared may vanish: a program cannot silently drop a shard it
    // was invoked with.
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

/// The `AccountData` an input describes: its balance, plus the one shard it carries if any.
///
/// Used only where no authoritative value exists, so the journalled claim is the starting point.
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
