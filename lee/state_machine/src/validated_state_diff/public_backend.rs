use lee_core::{
    BlockId, Commitment, Timestamp,
    account::{AccountId, Cycles, ProgramShardSelector, ShardData},
    execution_state::{ApplyPublicEffects, Backend, ExecutionState},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{
        ApplyInput, ApplyOutput, PROGRAM_LOADER_ACCOUNT_ID, PlanInput, PlanOutput, ProgramEvent,
        TransactionEvent,
    },
};
use log::debug;

use super::{Applier, charge, load_program, loader_shard, plan_program_loader, remaining};
use crate::{
    V03State, ensure,
    error::{InvalidProgramBehaviorError, LeeError},
};

pub(super) struct PublicBackend<'state> {
    state: &'state V03State,
    block_id: BlockId,
    timestamp: Timestamp,
    cycle_budget: Cycles,
    cycles_used: &'state mut Cycles,
    events: Vec<TransactionEvent>,
    new_commitments: Vec<Commitment>,
}

impl<'state> PublicBackend<'state> {
    pub(super) const fn new(
        state: &'state V03State,
        block_id: BlockId,
        timestamp: Timestamp,
        cycle_budget: Cycles,
        cycles_used: &'state mut Cycles,
    ) -> Self {
        Self {
            state,
            block_id,
            timestamp,
            cycle_budget,
            cycles_used,
            events: Vec::new(),
            new_commitments: Vec::new(),
        }
    }

    pub(super) fn into_outputs(self) -> (Vec<TransactionEvent>, Vec<Commitment>) {
        (self.events, self.new_commitments)
    }
}

impl Backend for PublicBackend<'_> {
    type Call = (AccountId, Applier);
    type Error = LeeError;
    type PublicEffects = ApplyPublicEffects;

    fn plan(
        &mut self,
        input: &PlanInput,
        execution: &ExecutionState<'_>,
    ) -> Result<(PlanOutput, Self::Call), LeeError> {
        let state = self.state;
        let self_account_id = input.self_account_id;
        debug!(
            "Program {self_account_id:?} accounts: {:?}, instruction_data: {:?}",
            input.accounts, input.instruction_data
        );
        let (plan, applier) = if self_account_id == PROGRAM_LOADER_ACCOUNT_ID {
            // `program_loader` runs as Rust, not a guest ELF, so there is no session to charge.
            const ABSENT: &ShardData = &ShardData::empty();
            let (plan, new_commitment) = plan_program_loader(input, |account_id| {
                loader_shard(execution, state, account_id).unwrap_or(ABSENT)
            })?;
            self.new_commitments.extend(new_commitment);
            (plan, Applier::Loader)
        } else if self_account_id == NATIVE_TOKEN_PROGRAM_ID {
            let plan = native_token::plan(
                input.caller_account_id,
                &input.accounts,
                &input.instruction_data,
            )
            .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?;
            (plan, Applier::Native)
        } else {
            let program = load_program(self_account_id, |account_id| {
                loader_shard(execution, state, account_id)
            })
            .ok_or(LeeError::UnknownProgram {
                chained: input.caller_account_id.is_some(),
            })?;
            let (plan, call_cycles) =
                program.plan(input, remaining(self.cycle_budget, *self.cycles_used))?;
            charge(self.cycles_used, call_cycles);
            (plan, Applier::Guest(program))
        };
        debug!("Program {self_account_id:?} plan: {plan:?}");
        Ok((plan, (self_account_id, applier)))
    }

    fn apply(
        &mut self,
        (_, applier): &mut Self::Call,
        input: &ApplyInput,
    ) -> Result<ApplyOutput, LeeError> {
        applier.apply(input, self.cycle_budget, self.cycles_used)
    }

    fn complete(
        &mut self,
        (self_account_id, _): Self::Call,
        events: Vec<ProgramEvent>,
        execution: &ExecutionState<'_>,
    ) -> Result<(), LeeError> {
        ensure!(
            execution
                .block_validity_window()
                .is_valid_for(self.block_id)
                && execution
                    .timestamp_validity_window()
                    .is_valid_for(self.timestamp),
            LeeError::OutOfValidityWindow
        );

        // Write all the output event data into a proper event struct,
        // marking its emitter program.
        self.events
            .extend(events.into_iter().map(|event| TransactionEvent {
                account_id: self_account_id,
                event,
            }));
        Ok(())
    }

    fn public_shard(
        &mut self,
        shard_selector: ProgramShardSelector,
    ) -> Result<ShardData, LeeError> {
        Ok(self
            .state
            .get_account_by_id_ref(shard_selector.account_id)
            .map_or_else(ShardData::empty, |account| {
                account
                    .data
                    .shard(shard_selector.program_account_id)
                    .clone()
            }))
    }
}
