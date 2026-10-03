use lee_core::program::{ReceiveInput, Response, run_actor};

// Hello-world with authorization example program.
//
// This program reads an arbitrary sequence of bytes as its message
// and appends those bytes to this program's own actor state on the receiving account.
//
// Execution succeeds only if the receiving account **is authorized**.

fn main() {
    run_actor(receive)
}

fn receive(input: &ReceiveInput, greeting: Vec<u8>) -> Response {
    // #### Difference with `hello_world` example here:
    // Fail if the receiving account is not authorized
    // The `is_authorized` field is set by the system from the account's signature or from a PDA
    // seed the sending program grants.
    assert!(input.is_authorized, "Missing required authorization");
    // ####

    let mut bytes = input.pre_state.to_vec();
    bytes.extend(greeting);
    Response::set_state(bytes)
}
