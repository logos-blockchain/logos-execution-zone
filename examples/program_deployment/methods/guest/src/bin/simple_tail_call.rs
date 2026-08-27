use lee_core::program::{AccountDiffOutput, ChainedCall, ProgramCall, ProgramId, read_lee_call};

// Tail Call example program.
//
// This program shows how to chain execution to another program using `ChainedCall`.
// It reads a single account, emits it unchanged, and then triggers a tail call
// to the Hello World program with a fixed greeting.

/// This needs to be set to the ID of the Hello world program.
/// To get the ID run **from the root directoy of the repository**:
/// `cargo risczero build --manifest-path examples/program_deployment/methods/guest/Cargo.toml`
/// This compiles the programs and outputs the IDs in hex that can be used to copy here.
const HELLO_WORLD_PROGRAM_ID_HEX: &str =
    "e9dfc5a5d03c9afa732adae6e0edfce4bbb44c7a2afb9f148f4309917eb2de6f";

fn hello_world_program_id() -> ProgramId {
    let hello_world_program_id_bytes: [u8; 32] = hex::decode(HELLO_WORLD_PROGRAM_ID_HEX)
        .unwrap()
        .try_into()
        .unwrap();
    bytemuck::cast(hello_world_program_id_bytes)
}

fn main() {
    // Read inputs
    let ProgramCall::Execute {
        input,
        instruction: (),
    } = read_lee_call::<()>();

    // Unpack the input account pre state
    let [pre_state] = input.pre_states.as_slice() else {
        panic!("Input pre states should consist of a single account");
    };

    // Create the (unchanged) post state
    let post_state = AccountDiffOutput::unchanged(pre_state.account_id);

    // Create the chained call
    let chained_call_greeting: Vec<u8> = b"Hello from tail call".to_vec();
    let chained_call_instruction_data = borsh::to_vec(&chained_call_greeting).unwrap();
    let chained_call = ChainedCall {
        program_id: hello_world_program_id(),
        instruction_data: chained_call_instruction_data,
        accounts: vec![pre_state.account_id],
        pda_seeds: vec![],
    };

    // Write the outputs.
    // WARNING: constructing a `ProgramOutput` has no effect on its own. `.write()` must be
    // called to commit the output.
    input
        .into_output(vec![post_state])
        .with_chained_calls(vec![chained_call])
        .write();
}
