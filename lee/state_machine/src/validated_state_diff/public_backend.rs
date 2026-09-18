//! The public environment's half of the shared traversal.
//!
//! What makes this environment public is concentrated here: it executes each program rather than
//! verifying a proof of it, it resolves every account value from committed chain state, and its
//! root authority is the transaction's signer set. The traversal in [`lee_core::validation`] owns
//! everything else.

use std::{borrow::Cow, collections::HashSet};

use lee_core::{
    BlockId, Timestamp,
    account::{Account, AccountId, AccountWithMetadata, Cycles},
    program::{
        AccountStateDiff, BlockValidityWindow, ChainedCall, PROGRAM_LOADER_ACCOUNT_ID,
        ProgramEvent, ProgramOutput, TimestampValidityWindow, TransactionEvent,
        UnsupportedCallKind, compute_public_authorized_pdas, get_program_via,
    },
    validation::{Backend, CallContext},
};
use log::debug;

use crate::{
    V03State, ensure,
    error::{InvalidProgramBehaviorError, LeeError},
    program::Program,
    validated_state_diff::execute_program_loader,
};

pub struct PublicBackend<'state> {
    state: &'state V03State,
    block_id: BlockId,
    timestamp: Timestamp,
    /// Accounts the transaction named up front. An account not declared here and not already
    /// written by an earlier call is unreachable: a chained call may not reach into global state.
    declared_account_ids: HashSet<AccountId>,
    /// Root authority. Every other environment grants this at first sight of a credential; here
    /// it is a signature, known before the first program runs.
    signers: HashSet<AccountId>,
    cycle_budget: Cycles,
    cycles_used: Cycles,
    events: Vec<TransactionEvent>,
    /// Recomputed once per call in `output_for_call`, which the traversal always runs before the
    /// per-account hooks, so deriving it per account would only repeat the hashing.
    authorized_pdas: HashSet<AccountId>,
}

impl<'state> PublicBackend<'state> {
    pub fn new(
        state: &'state V03State,
        block_id: BlockId,
        timestamp: Timestamp,
        declared_account_ids: &[AccountId],
        signers: &HashSet<AccountId>,
        cycle_budget: Cycles,
    ) -> Self {
        Self {
            state,
            block_id,
            timestamp,
            declared_account_ids: declared_account_ids.iter().copied().collect(),
            signers: signers.clone(),
            cycle_budget,
            cycles_used: 0,
            events: Vec::new(),
            authorized_pdas: HashSet::new(),
        }
    }

    pub const fn cycles_used(&self) -> Cycles {
        self.cycles_used
    }

    pub fn into_events(self) -> Vec<TransactionEvent> {
        self.events
    }

    /// An account is authorized when a signature covers it, when a caller delegated a seed that
    /// derives it, or when an earlier call in this branch already established it.
    fn is_authorized(&self, ctx: &CallContext<'_>, account_id: AccountId) -> bool {
        self.signers.contains(&account_id)
            || self.authorized_pdas.contains(&account_id)
            || ctx.authorized_accounts.contains(&account_id)
    }

    /// The caller only names which accounts to call with; resolve their actual values from the
    /// protocol's own tracked state, never from anything the caller asserts. Resolvable only if
    /// declared up front or already touched in this transaction, never merely because the
    /// account exists somewhere in global state.
    fn resolve_pre_states(
        &self,
        call: &ChainedCall,
        ctx: &CallContext<'_>,
    ) -> Result<Vec<AccountWithMetadata>, LeeError> {
        call.pre_state_ids
            .iter()
            .map(|account_id| {
                let account = match ctx.touched.get(account_id) {
                    Some(account) => account.clone(),
                    None if self.declared_account_ids.contains(account_id) => {
                        self.state.get_account_by_id(*account_id)
                    }
                    None => {
                        return Err(LeeError::from(
                            InvalidProgramBehaviorError::UnknownChainedCallAccount {
                                account_id: *account_id,
                            },
                        ));
                    }
                };
                Ok(AccountWithMetadata::new(
                    account,
                    self.is_authorized(ctx, *account_id),
                    *account_id,
                ))
            })
            .collect()
    }
}

impl Backend for PublicBackend<'_> {
    type Error = LeeError;

    fn output_for_call(
        &mut self,
        call: &ChainedCall,
        ctx: &CallContext<'_>,
    ) -> Result<ProgramOutput, LeeError> {
        self.authorized_pdas =
            compute_public_authorized_pdas(ctx.caller_account_id, &call.pda_seeds);

        let pre_states = self.resolve_pre_states(call, ctx)?;

        debug!(
            "Program {:?} pre_states: {:?}, instruction_data: {:?}",
            call.program_account_id, pre_states, call.instruction_data
        );

        let program_output = if call.program_account_id == PROGRAM_LOADER_ACCOUNT_ID {
            // Native dispatch: `program_loader` is a pseudo-program run as Rust rather than a
            // guest ELF, so there is no zkVM session to charge cycles against.
            execute_program_loader(
                call.program_account_id,
                ctx.caller_account_id,
                &pre_states,
                &call.instruction_data,
            )?
        } else {
            // Looks through the in-flight diff first, so a program an earlier chained call in
            // this same transaction deployed is callable immediately.
            let Some((program_id, user_elf)) = get_program_via(call.program_account_id, |id| {
                ctx.touched
                    .get(&id)
                    .cloned()
                    .unwrap_or_else(|| self.state.get_account_by_id(id))
            }) else {
                return Err(LeeError::UnknownProgram {
                    chained: ctx.caller_account_id.is_some(),
                });
            };
            let elf = crate::program::attach_kernel(&user_elf);
            let program = Program::new_unchecked(program_id, Cow::Owned(elf));
            let (program_output, call_cycles) = program.execute(
                call.program_account_id,
                ctx.caller_account_id,
                &pre_states,
                &call.instruction_data,
                self.cycle_budget.saturating_sub(self.cycles_used),
            )?;
            self.cycles_used = self
                .cycles_used
                .checked_add(call_cycles)
                .expect("cycle sums fit u64: overflow would need ~2^64 executed cycles");
            program_output
        };

        debug!(
            "Program {:?} output: {:?}",
            call.program_account_id, program_output
        );

        Ok(program_output)
    }

    fn expected_first_sight(
        &mut self,
        account_id: AccountId,
        _ctx: &CallContext<'_>,
    ) -> Result<Option<Account>, LeeError> {
        Ok(Some(self.state.get_account_by_id(account_id)))
    }

    fn judge_authorization(
        &mut self,
        pre: &AccountWithMetadata,
        _position: usize,
        _first_sight: bool,
        ctx: &CallContext<'_>,
    ) -> Result<bool, LeeError> {
        let account_id = pre.account_id;
        let is_indeed_authorized = self.is_authorized(ctx, account_id);
        ensure!(
            !pre.is_authorized || is_indeed_authorized,
            InvalidProgramBehaviorError::InvalidAccountAuthorization { account_id }
        );
        ensure!(
            pre.is_authorized || !is_indeed_authorized,
            InvalidProgramBehaviorError::AuthorizedAccountMarkedAsNotAuthorized { account_id }
        );
        // The public environment exports exactly what the program journalled: here the verifier
        // is the executor, so there is no second view of authorization to reconcile.
        Ok(pre.is_authorized)
    }

    /// Runs `diff`'s producing program via `CallKind::Incremental` against the account's real
    /// current state, falling back to `diff` verbatim if the program hasn't implemented
    /// `Incremental` (an `UnsupportedCallKind` event). `program_loader` is exempt - a native
    /// pseudo-program with no guest ELF to run.
    fn resolve_write(
        &mut self,
        diff: &AccountStateDiff,
        ctx: &CallContext<'_>,
    ) -> Result<AccountStateDiff, LeeError> {
        if ctx.program_account_id == PROGRAM_LOADER_ACCOUNT_ID {
            return Ok(diff.clone());
        }
        let Some(post_data) = diff.post_data.as_ref() else {
            return Ok(diff.clone());
        };

        let account_id = diff.pre_state.account_id;
        let real_pre_state = AccountWithMetadata::new(
            ctx.touched
                .get(&account_id)
                .cloned()
                .unwrap_or_else(|| self.state.get_account_by_id(account_id)),
            diff.pre_state.is_authorized,
            account_id,
        );

        let Some((program_id, user_elf)) = get_program_via(ctx.program_account_id, |id| {
            ctx.touched
                .get(&id)
                .cloned()
                .unwrap_or_else(|| self.state.get_account_by_id(id))
        }) else {
            return Err(LeeError::UnknownProgram {
                chained: ctx.caller_account_id.is_some(),
            });
        };
        let elf = crate::program::attach_kernel(&user_elf);
        let program = Program::new_unchecked(program_id, Cow::Owned(elf));

        let (incremental_output, incremental_cycles) = program.execute_incremental(
            ctx.program_account_id,
            &real_pre_state,
            post_data,
            self.cycle_budget.saturating_sub(self.cycles_used),
        )?;
        self.cycles_used = self
            .cycles_used
            .checked_add(incremental_cycles)
            .expect("cycle sums fit u64: overflow would need ~2^64 executed cycles");

        if incremental_output
            .events
            .iter()
            .any(|event| event.selector == UnsupportedCallKind::SELECTOR)
        {
            return Ok(diff.clone());
        }

        let [resolved]: [AccountStateDiff; 1] =
            incremental_output
                .state_diffs
                .try_into()
                .map_err(|diffs: Vec<AccountStateDiff>| {
                    InvalidProgramBehaviorError::MalformedIncrementalResponse {
                        program_account_id: ctx.program_account_id,
                        account_id,
                        reason: format!("expected exactly 1 diff, got {}", diffs.len()),
                    }
                })?;
        ensure!(
            resolved.pre_state.account_id == account_id,
            InvalidProgramBehaviorError::MalformedIncrementalResponse {
                program_account_id: ctx.program_account_id,
                account_id,
                reason: format!(
                    "returned a diff for {} instead",
                    resolved.pre_state.account_id
                ),
            }
        );

        Ok(resolved)
    }

    fn observe_windows(
        &mut self,
        block: BlockValidityWindow,
        timestamp: TimestampValidityWindow,
    ) -> Result<(), LeeError> {
        ensure!(
            block.is_valid_for(self.block_id) && timestamp.is_valid_for(self.timestamp),
            LeeError::OutOfValidityWindow
        );
        Ok(())
    }

    fn observe_events(&mut self, emitter: AccountId, events: Vec<ProgramEvent>) {
        self.events
            .extend(events.into_iter().map(|event| TransactionEvent {
                account_id: emitter,
                event,
            }));
    }
}
