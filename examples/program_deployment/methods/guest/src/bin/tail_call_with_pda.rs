use nssa_core::program::{
    AccountPostState, ChainedCall, PdaSeed, ProgramId, ProgramInput, read_nssa_inputs,
    write_nssa_outputs_with_chained_call,
};

// Tail Call with PDA example program.
//
// Demonstrates how to chain execution to another program using `ChainedCall`
// while authorizing program-derived accounts.
//
// Expects a single input account whose Account ID is derived from this
// program’s ID and the fixed PDA seed below (as defined by the
// `<AccountId as From<(&ProgramId, &PdaSeed)>>` implementation).
//
// Emits this account unchanged, then performs a tail call to the
// Hello-World-with-Authorization program with a fixed greeting. The same
// account is passed along but marked with `is_authorized = true`.

const HELLO_WORLD_WITH_AUTHORIZATION_PROGRAM_ID_HEX: &str =
    "60a0cc3d560cba06ba65f02ca70db7828e448a15f320eb7d0fd48e7fb1fa5a3e";
const PDA_SEED: PdaSeed = PdaSeed::new([37; 32]);

fn hello_world_program_id() -> ProgramId {
    let hello_world_program_id_bytes: [u8; 32] =
        hex::decode(HELLO_WORLD_WITH_AUTHORIZATION_PROGRAM_ID_HEX)
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
    let chained_call_greeting: Vec<u8> =
        b"Hello from tail call with Program Derived Account ID".to_vec();
    let chained_call_instruction_data = risc0_zkvm::serde::to_vec(&chained_call_greeting).unwrap();

    // Flip the `is_authorized` flag to true
    let pre_state_for_chained_call = {
        let mut this = pre_state.clone();
        this.is_authorized = true;
        this
    };
    let chained_call = ChainedCall {
        program_id: hello_world_program_id(),
        instruction_data: chained_call_instruction_data,
        pre_states: vec![pre_state_for_chained_call],
        pda_seeds: vec![PDA_SEED],
    };

    // Write the outputs
    write_nssa_outputs_with_chained_call(
        instruction_data,
        vec![pre_state],
        vec![post_state],
        vec![chained_call],
    );
}
