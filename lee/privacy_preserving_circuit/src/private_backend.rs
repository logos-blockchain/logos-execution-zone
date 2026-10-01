//! The privacy preserving circuit's half of the shared traversal: it verifies a receipt for each
//! private turn.

use std::{collections::HashMap, convert::Infallible, vec};

use lee_core::{
    account::AccountId,
    execution_state::{Backend, ExecutionError, ExecutionState},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{ProgramId, ReceiveInput, Transition},
};
use risc0_zkvm::guest::env;

pub struct PrivateBackend {
    image_ids: HashMap<AccountId, ProgramId>,
    turns: vec::IntoIter<Transition>,
}

impl PrivateBackend {
    pub fn new(image_ids: HashMap<AccountId, ProgramId>, turns: Vec<Transition>) -> Self {
        Self {
            image_ids,
            turns: turns.into_iter(),
        }
    }

    pub fn finish(mut self) {
        assert!(
            self.turns.next().is_none(),
            "A transition was supplied for a turn nothing scheduled"
        );
    }
}

impl Backend for PrivateBackend {
    type Error = ExecutionError;

    fn receive(
        &mut self,
        input: &ReceiveInput,
        _execution: &ExecutionState<'_>,
    ) -> Result<Transition, ExecutionError> {
        let program = input.receiver.program_account_id;
        if program == NATIVE_TOKEN_PROGRAM_ID {
            return Ok(native_token::receive(input).unwrap_or_else(|e| panic!("{e}")));
        }
        let image_id = *self
            .image_ids
            .get(&program)
            .expect("no image_id claim supplied for invoked program account");
        let transition = self
            .turns
            .next()
            .expect("a scheduled turn must carry its transition");
        env::verify(image_id, &lee_core::to_borsh_frame(&transition))
            .unwrap_or_else(|_: Infallible| unreachable!("Infallible error is never constructed"));
        Ok(transition)
    }
}
