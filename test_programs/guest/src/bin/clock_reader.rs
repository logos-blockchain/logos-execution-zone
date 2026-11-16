//! Clock reader program.
//!
//! Forwards any other message it is sent to the clock, and stores the clock's reply as its state.

use std::collections::BTreeSet;

use lee_core::program::{ReceiveInput, Response, SyncMessage};

lee_core::actor_entrypoint!(raw handle_message);

fn handle_message(input: &ReceiveInput) -> Response {
    let clock = clock_core::clock_actor();
    if input.from == Some(clock) {
        return Response::set_state(input.message.clone());
    }
    Response::keep_state().send(SyncMessage {
        to: clock,
        message: input.message.clone(),
        pda_seeds: BTreeSet::new(),
    })
}
