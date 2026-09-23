//! The public environment's half of the shared traversal: it executes each program and
//! resolves every shard from committed chain state, with the signer set as root authority.

use std::{borrow::Cow, collections::HashSet};

use lee_core::{
    BlockId, Timestamp,
    account::{AccountData, AccountId, Cycles},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{
        AccountInput, BlockValidityWindow, ChainedCall, PROGRAM_LOADER_ACCOUNT_ID, ProgramEvent,
        ProgramOutput, TimestampValidityWindow, TransactionEvent, compute_public_authorized_pdas,
        get_program_via,
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
    /// An account neither declared here nor already written is unreachable.
    declared_account_ids: HashSet<AccountId>,
    signers: HashSet<AccountId>,
    cycle_budget: Cycles,
    cycles_used: Cycles,
    events: Vec<TransactionEvent>,
    /// Recomputed per call in `output_for_call`, which always runs before the per-account hooks.
    authorized_pdas: HashSet<AccountId>,
}

impl<'state> PublicBackend<'state> {
    pub fn new(
        state: &'state V03State,
        block_id: BlockId,
        timestamp: Timestamp,
        declared_account_ids: HashSet<AccountId>,
        signers: &HashSet<AccountId>,
        cycle_budget: Cycles,
    ) -> Self {
        Self {
            state,
            block_id,
            timestamp,
            declared_account_ids,
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

    fn is_authorized(&self, ctx: &CallContext<'_>, account_id: AccountId) -> bool {
        self.signers.contains(&account_id)
            || self.authorized_pdas.contains(&account_id)
            || ctx.authorized_accounts.contains(&account_id)
    }

    /// An earlier call's result if there is one, else committed state. Borrowed, so callers
    /// clone only the shard they need.
    fn tracked_ref<'call>(
        &'call self,
        ctx: &'call CallContext<'_>,
        account_id: AccountId,
    ) -> Option<&'call AccountData> {
        ctx.touched.get(&account_id).or_else(|| {
            self.state
                .get_account_by_id_ref(account_id)
                .map(|account| &account.data)
        })
    }

    /// Resolve each named selector from tracked state, never from what the caller asserts, and
    /// only if declared up front or already touched: existing in global state is not enough.
    fn resolve_pre_states(
        &self,
        call: &ChainedCall,
        ctx: &CallContext<'_>,
    ) -> Result<Vec<AccountInput>, LeeError> {
        // One absent value to borrow for declared accounts that do not exist yet.
        let absent = AccountData::default();
        call.shard_selectors
            .iter()
            .map(|shard_selector| {
                let account_id = shard_selector.account_id;
                let data = match self.tracked_ref(ctx, account_id) {
                    Some(data) => data,
                    None if self.declared_account_ids.contains(&account_id) => &absent,
                    None => {
                        return Err(LeeError::from(
                            InvalidProgramBehaviorError::UnknownChainedCallAccount { account_id },
                        ));
                    }
                };
                Ok(AccountInput::at(
                    *shard_selector,
                    self.is_authorized(ctx, account_id),
                    data,
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

        let program_output = if call.program_account_id == NATIVE_TOKEN_PROGRAM_ID {
            native_token::execute(ctx.caller_account_id, &pre_states, &call.instruction_data)
                .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?
        } else if call.program_account_id == PROGRAM_LOADER_ACCOUNT_ID {
            // `program_loader` runs as Rust, not a guest ELF, so there is no session to charge.
            execute_program_loader(
                call.program_account_id,
                ctx.caller_account_id,
                &pre_states,
                &call.instruction_data,
            )?
        } else {
            // Through the in-flight diff first, so a program deployed by an earlier call in this
            // transaction is callable immediately.
            let Some((program_id, user_elf)) = get_program_via(call.program_account_id, |id| {
                ctx.touched.get(&id).or_else(|| {
                    self.state
                        .get_account_by_id_ref(id)
                        .map(|account| &account.data)
                })
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

    fn has_independent_view(&mut self, _account_id: AccountId) -> bool {
        // Chain state is always a view, even for an account that does not exist yet.
        true
    }

    fn value_at_first_sight(
        &mut self,
        account_id: AccountId,
        ctx: &CallContext<'_>,
    ) -> Result<Option<AccountData>, LeeError> {
        Ok(Some(
            self.tracked_ref(ctx, account_id)
                .cloned()
                .unwrap_or_default(),
        ))
    }

    fn judge_authorization(
        &mut self,
        pre: &AccountInput,
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
        // The verifier is the executor here, so there is no second view to reconcile.
        Ok(pre.is_authorized)
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
