use lee_core::{
    Commitment,
    account::{Actor, ActorState, Cycles},
    execution_state::{ExecutionEnvironment, TurnView},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{PROGRAM_LOADER_ACCOUNT_ID, ReceiveInput, Transition},
};
use log::debug;

use super::{catch_program_loader_panic, charge, load_program, loader_shard, remaining};
use crate::{
    V03State,
    error::{InvalidProgramBehaviorError, LeeError},
};

pub(super) struct PublicBackend<'state> {
    state: &'state V03State,
    cycle_budget: Cycles,
    cycles_used: &'state mut Cycles,
    program_commitments: Vec<Commitment>,
}

impl<'state> PublicBackend<'state> {
    pub(super) const fn new(
        state: &'state V03State,
        cycle_budget: Cycles,
        cycles_used: &'state mut Cycles,
    ) -> Self {
        Self {
            state,
            cycle_budget,
            cycles_used,
            program_commitments: Vec::new(),
        }
    }

    pub(super) fn into_program_commitments(self) -> Vec<Commitment> {
        self.program_commitments
    }
}

impl ExecutionEnvironment for PublicBackend<'_> {
    type Error = LeeError;

    fn receive(
        &mut self,
        input: &ReceiveInput,
        view: &TurnView<'_>,
    ) -> Result<Transition, LeeError> {
        let state = self.state;
        let program_account_id = input.receiver.program_account_id;
        debug!("Program {program_account_id:?} input: {input:?}");
        let transition = if program_account_id == PROGRAM_LOADER_ACCOUNT_ID {
            // `program_loader` runs as Rust, not a guest ELF, so there is no session to charge.
            const ABSENT: &ActorState = &ActorState::empty();
            let (transition, new_commitment) = catch_program_loader_panic(|| {
                program_loader_core::receive(input, |account_id| {
                    loader_shard(view, state, account_id).unwrap_or(ABSENT)
                })
            })?;
            self.program_commitments.extend(new_commitment);
            transition
        } else if program_account_id == NATIVE_TOKEN_PROGRAM_ID {
            native_token::receive(input)
                .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?
        } else {
            let program = load_program(program_account_id, |account_id| {
                loader_shard(view, state, account_id)
            })
            .ok_or(LeeError::UnknownProgram {
                at_root: view.at_root(),
            })?;
            let (transition, call_cycles) =
                program.receive(input, remaining(self.cycle_budget, *self.cycles_used))?;
            charge(self.cycles_used, call_cycles);
            transition
        };
        debug!("Program {program_account_id:?} transition: {transition:?}");
        Ok(transition)
    }

    fn public_actor_state(&mut self, actor: Actor) -> Result<ActorState, LeeError> {
        Ok(self
            .state
            .get_account_by_id_ref(actor.account_id)
            .map_or_else(ActorState::empty, |account| {
                account.data.shard(actor.program_account_id).clone()
            }))
    }
}
