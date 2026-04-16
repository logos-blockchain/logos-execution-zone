use nssa_core::{
    Timestamp,
    program::{
        AccountPostState, ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_nssa_inputs,
    },
};
use risc0_zkvm::serde::to_vec;

type Instruction = (ProgramId, Timestamp); // (clock_program_id, timestamp)

/// A program that chain-calls the clock program with the clock accounts it received as pre-states.
/// Used in tests to verify that user transactions cannot modify clock accounts, even indirectly
/// via chain calls.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (clock_program_id, timestamp),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let post_states: Vec<_> = pre_states
        .iter()
        .map(|pre| AccountPostState::new(pre.account.clone()))
        .collect();

    let chained_call = ChainedCall {
        program_id: clock_program_id,
        instruction_data: to_vec(&timestamp).unwrap(),
        pre_states: pre_states.clone(),
        pda_seeds: vec![],
        private_pda_seeds: vec![],
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
