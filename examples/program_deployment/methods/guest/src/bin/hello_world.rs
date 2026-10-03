use lee_core::program::{ReceiveInput, Response, run_actor};

// Hello-world example program.
//
// This program reads an arbitrary sequence of bytes as its message
// and appends those bytes to this program's own actor state on the receiving account.

fn main() {
    run_actor(receive)
}

fn receive(input: &ReceiveInput, greeting: Vec<u8>) -> Response {
    let mut bytes = input.pre_state.to_vec();
    bytes.extend(greeting);
    Response::set_state(bytes)
}
