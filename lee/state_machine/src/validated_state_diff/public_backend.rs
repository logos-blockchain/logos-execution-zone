//! The public environment's half of the shared traversal: it executes each program and
//! resolves every shard from committed chain state, with the signer set as root authority.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

use lee_core::{
    BlockId, Commitment, Timestamp,
    account::{AccountData, AccountId, Cycles},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{
        AccountInput, BlockValidityWindow, ChainedCall, PROGRAM_LOADER_ACCOUNT_ID, ProgramEvent,
        ProgramOutput, TimestampValidityWindow, TransactionEvent, compute_public_authorized_pdas,
    },
    validation::{AccountSource, Backend, CallContext, TrackedAccount},
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
    new_commitments: Vec<Commitment>,
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
            new_commitments: Vec::new(),
            authorized_pdas: HashSet::new(),
        }
    }

    pub const fn cycles_used(&self) -> Cycles {
        self.cycles_used
    }

    pub fn into_outputs(self) -> (Vec<TransactionEvent>, Vec<Commitment>) {
        (self.events, self.new_commitments)
    }

    fn is_authorized(&self, ctx: &CallContext<'_>, account_id: AccountId) -> bool {
        self.signers.contains(&account_id)
            || self.authorized_pdas.contains(&account_id)
            || ctx.authorized_accounts.contains(&account_id)
    }

    /// Resolve each named selector from tracked state, never from what the caller asserts, and
    /// only if declared up front or already touched.
    fn resolve_pre_states(
        &self,
        call: &ChainedCall,
        ctx: &CallContext<'_>,
        accounts: &HashMap<AccountId, TrackedAccount>,
    ) -> Result<Vec<AccountInput>, LeeError> {
        // One absent value to borrow for declared accounts that do not exist yet.
        let absent = AccountData::default();
        call.shard_selectors
            .iter()
            .map(|shard_selector| {
                let account_id = shard_selector.account_id;
                let data = match accounts.get(&account_id) {
                    Some(account) => &account.current,
                    None if self.declared_account_ids.contains(&account_id) => self
                        .state
                        .get_account_by_id_ref(account_id)
                        .map_or(&absent, |account| &account.data),
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
        accounts: &HashMap<AccountId, TrackedAccount>,
    ) -> Result<ProgramOutput, LeeError> {
        self.authorized_pdas =
            compute_public_authorized_pdas(ctx.caller_account_id, &call.pda_seeds);

        let pre_states = self.resolve_pre_states(call, ctx, accounts)?;

        debug!(
            "Program {:?} pre_states: {:?}, instruction_data: {:?}",
            call.program_account_id, pre_states, call.instruction_data
        );

        let program_output = if call.program_account_id == NATIVE_TOKEN_PROGRAM_ID {
            native_token::execute(ctx.caller_account_id, &pre_states, &call.instruction_data)
                .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?
        } else if call.program_account_id == PROGRAM_LOADER_ACCOUNT_ID {
            // `program_loader` runs as Rust, not a guest ELF, so there is no session to charge.
            let (program_output, new_commitment) = execute_program_loader(
                call.program_account_id,
                ctx.caller_account_id,
                &pre_states,
                &call.instruction_data,
            )?;
            self.new_commitments.extend(new_commitment);
            program_output
        } else {
            let Some((program_id, elf)) =
                crate::program::resolve_program(call.program_account_id, |id| {
                    accounts
                        .get(&id)
                        .map(|account| &account.current)
                        .or_else(|| {
                            self.state
                                .get_account_by_id_ref(id)
                                .map(|account| &account.data)
                        })
                })
            else {
                return Err(LeeError::UnknownProgram {
                    chained: ctx.caller_account_id.is_some(),
                });
            };
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

    fn account_source(&self, account_id: AccountId) -> AccountSource {
        // Chain state is always a view, even for an account that does not exist yet.
        AccountSource::Authoritative(
            self.state
                .get_account_by_id_ref(account_id)
                .map(|account| account.data.clone())
                .unwrap_or_default(),
        )
    }

    fn judge_authorization(
        &mut self,
        pre: &AccountInput,
        _prior_export: Option<bool>,
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
