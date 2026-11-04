//! Clock reader program.
//!
//! Forwards any other message it is sent to the clock, and stores the clock's reply as its state.

use std::collections::BTreeSet;

use clock_core::{CLOCK_PROGRAM_ACCOUNT_ID, Reply};
use lee_core::{
    account::Actor,
    program::{ReceiveInput, Response, SyncMessage},
};

lee_core::actor_entrypoint!(raw handle_message);

fn handle_message(input: &ReceiveInput) -> Response {
    if Reply::from_input(input).is_some() {
        return Response::set_state(input.message.clone());
    }
    Response::keep_state().send(SyncMessage {
        to: Actor::new(CLOCK_PROGRAM_ACCOUNT_ID, clock_core::clock_account_id()),
        message: input.message.clone(),
        pda_seeds: BTreeSet::new(),
    })
}
