use nssa_core::program::{
    AccountPostState, ChainedCall, ProgramId, ProgramInput, read_nssa_inputs,
    write_nssa_outputs_with_chained_call,
};

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
    "075d33a4ffe411d14df68194c0d4a416abed564b3eb788649cabeb730f393258";

fn hello_world_program_id() -> ProgramId {
    let hello_world_program_id_bytes: [u8; 32] = hex::decode(HELLO_WORLD_PROGRAM_ID_HEX)
        .unwrap()
        .try_into()
        .unwrap();
    bytemuck::cast(hello_world_program_id_bytes)
}

fn main() {
    // Read inputs
    let (
        ProgramInput {
            pre_states,
            instruction: _,
        },
        instruction_data,
    ) = read_nssa_inputs::<()>();

    // Unpack the input account pre state
    let [pre_state] = pre_states
        .clone()
        .try_into()
        .unwrap_or_else(|_| panic!("Input pre states should consist of a single account"));

    // Create the (unchanged) post state
    let post_state = AccountPostState::new(pre_state.account.clone());

    // Create the chained call
    let chained_call_greeting: Vec<u8> = b"Hello from tail call".to_vec();
    let chained_call_instruction_data = risc0_zkvm::serde::to_vec(&chained_call_greeting).unwrap();
    let chained_call = ChainedCall {
        program_id: hello_world_program_id(),
        instruction_data: chained_call_instruction_data,
        pre_states,
        pda_seeds: vec![],
    };

    // Write the outputs
    write_nssa_outputs_with_chained_call(
        instruction_data,
        vec![pre_state],
        vec![post_state],
        vec![chained_call],
    );
}
