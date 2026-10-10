use std::collections::BTreeSet;

use lee_core::{
    Commitment,
    account::{AccountId, Actor, ActorState, Cycles},
    execution_state::{ExecutionEnvironment, ExecutionError, Placement, TransitionView},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{MessageBody, PROGRAM_LOADER_ACCOUNT_ID, ReceiveInput, Transition},
};
use log::debug;

use super::{catch_program_loader_panic, load_program, loader_actor_state};
use crate::{
    V03State,
    error::{InvalidProgramBehaviorError, LeeError},
};

pub(super) struct PublicBackend<'state> {
    state: &'state V03State,
    cycle_budget: Cycles,
    cycles_used: &'state mut Cycles,
    program_commitments: Vec<Commitment>,
    cast_promotions: BTreeSet<u64>,
    evidence: BTreeSet<AccountId>,
}

impl<'state> PublicBackend<'state> {
    pub(super) const fn new(
        state: &'state V03State,
        cycle_budget: Cycles,
        cycles_used: &'state mut Cycles,
        cast_promotions: BTreeSet<u64>,
        evidence: BTreeSet<AccountId>,
    ) -> Self {
        Self {
            state,
            cycle_budget,
            cycles_used,
            program_commitments: Vec::new(),
            cast_promotions,
            evidence,
        }
    }

    pub(super) const fn state(&self) -> &'state V03State {
        self.state
    }

    pub(super) fn finish(self) -> Result<Vec<Commitment>, LeeError> {
        if let Some(&index) = self.cast_promotions.first() {
            return Err(ExecutionError::UnreachedCastPromotion { index }.into());
        }
        Ok(self.program_commitments)
    }
}

impl ExecutionEnvironment for PublicBackend<'_> {
    type Error = LeeError;

    fn handle_message(
        &mut self,
        input: &ReceiveInput,
        view: &TransitionView<'_>,
    ) -> Result<Transition, LeeError> {
        let state = self.state;
        let program_account_id = input.receiver.program_account_id;
        debug!("Program {program_account_id:?} input: {input:?}");
        let transition = if program_account_id == PROGRAM_LOADER_ACCOUNT_ID {
            // `program_loader` runs as Rust, not a guest ELF, so there is no session to charge.
            const ABSENT: &ActorState = &ActorState::empty();
            let (transition, new_commitment) = catch_program_loader_panic(|| {
                program_loader_core::handle_message(input, |account_id| {
                    loader_actor_state(view, state, account_id).unwrap_or(ABSENT)
                })
            })?;
            self.program_commitments.extend(new_commitment);
            transition
        } else if program_account_id == NATIVE_TOKEN_PROGRAM_ID {
            native_token::handle_message(input)
                .map_err(InvalidProgramBehaviorError::NativeTransferFailed)?
        } else {
            let program = load_program(program_account_id, |account_id| {
                loader_actor_state(view, state, account_id)
            })
            .ok_or(LeeError::UnknownProgram {
                at_root: view.at_root(),
            })?;
            program.handle_message_metered(input, self.cycle_budget, self.cycles_used)?
        };
        debug!("Program {program_account_id:?} transition: {transition:?}");
        Ok(transition)
    }

    fn public_actor_state(&mut self, actor: Actor) -> Result<ActorState, LeeError> {
        Ok(self
            .state
            .get_account_by_id_ref(actor.account_id)
            .map_or_else(ActorState::empty, |account| {
                account.data.actor_state(actor.program_account_id).clone()
            }))
    }

    fn admits(&mut self, account_id: AccountId) -> Result<bool, LeeError> {
        Ok(self.state.get_account_by_id_ref(account_id).is_some()
            || self.evidence.contains(&account_id))
    }

    fn promote(
        &mut self,
        placement: Placement,
        index: u64,
        _body: &MessageBody,
    ) -> Result<bool, LeeError> {
        Ok(placement == Placement::Public && self.cast_promotions.remove(&index))
    }
}
