//! The privacy preserving circuit's half of the shared traversal: it verifies a receipt for each
//! private transition.

use std::{
    collections::{BTreeSet, HashMap},
    convert::Infallible,
    vec,
};

use lee_core::{
    SenderPresentation,
    account::{AccountId, Actor},
    execution_state::{ExecutionEnvironment, ExecutionError, Placement, TransitionView},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{MessageBody, ProgramId, ReceiveInput, Response, Transition},
};
use risc0_zkvm::guest::env;

pub struct PrivateBackend {
    image_ids: HashMap<AccountId, ProgramId>,
    responses: vec::IntoIter<Response>,
    sender_presentations: vec::IntoIter<SenderPresentation>,
    cast_promotions: BTreeSet<u64>,
}

impl PrivateBackend {
    pub fn new(
        image_ids: HashMap<AccountId, ProgramId>,
        responses: Vec<Response>,
        sender_presentations: Vec<SenderPresentation>,
        cast_promotions: BTreeSet<u64>,
    ) -> Self {
        Self {
            image_ids,
            responses: responses.into_iter(),
            sender_presentations: sender_presentations.into_iter(),
            cast_promotions,
        }
    }

    pub fn finish(mut self) {
        assert!(
            self.responses.next().is_none(),
            "A response was supplied for a transition nothing scheduled"
        );
        assert!(
            self.sender_presentations.next().is_none(),
            "A sender presentation was supplied for a message nothing sent"
        );
        if let Some(&index) = self.cast_promotions.first() {
            panic!("{}", ExecutionError::UnreachedCastPromotion { index });
        }
    }
}

impl ExecutionEnvironment for PrivateBackend {
    type Error = ExecutionError;

    fn handle_message(
        &mut self,
        input: &ReceiveInput,
        _execution: &TransitionView<'_>,
    ) -> Result<Transition, ExecutionError> {
        let program = input.receiver.program_account_id;
        if program == NATIVE_TOKEN_PROGRAM_ID {
            return Ok(native_token::handle_message(input).unwrap_or_else(|e| panic!("{e}")));
        }
        let image_id = *self
            .image_ids
            .get(&program)
            .expect("no image_id claim supplied for invoked program account");
        let transition = self
            .responses
            .next()
            .expect("a scheduled transition must carry its response")
            .into_transition(input.clone());
        env::verify(image_id, &lee_core::to_borsh_frame(&transition))
            .unwrap_or_else(|_: Infallible| unreachable!("Infallible error is never constructed"));
        Ok(transition)
    }

    fn present(&mut self, sender: Actor) -> Result<SenderPresentation, ExecutionError> {
        self.sender_presentations
            .next()
            .ok_or(ExecutionError::MissingSenderPresentation { sender })
    }

    fn promote(
        &mut self,
        placement: Placement,
        index: u64,
        _body: &MessageBody,
    ) -> Result<bool, ExecutionError> {
        Ok(placement == Placement::Private && self.cast_promotions.remove(&index))
    }
}
