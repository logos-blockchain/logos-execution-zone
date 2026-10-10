use lee_core::{
    account::Actor,
    program::{ReceiveInput, Response},
};

// Tail Call example program.
//
// Keeps its own actor state unchanged and sends a fixed greeting to the callee actor named in its
// message.
//
// The callee is caller-supplied: a deployed program's address isn't known until deploy time, so
// it can't be a compile-time constant.

lee_core::define_actor_logic!(handle_message);

fn handle_message(_input: &ReceiveInput, callee: Actor) -> Response {
    let greeting: Vec<u8> = b"Hello from tail call".to_vec();

    Response::keep_state().call(callee, &greeting)
}
