use lee_core::{
    account::Actor,
    program::{ReceiveInput, Response, run_actor},
};

// Tail Call example program.
//
// Keeps its own shard unchanged and sends a fixed greeting to the callee actor named in its
// message.
//
// The callee is caller-supplied: a deployed program's address isn't known until deploy time, so
// it can't be a compile-time constant.

fn main() {
    run_actor(receive)
}

fn receive(_input: &ReceiveInput, callee: Actor) -> Response {
    let greeting: Vec<u8> = b"Hello from tail call".to_vec();

    Response::keep().call(callee, &greeting)
}
