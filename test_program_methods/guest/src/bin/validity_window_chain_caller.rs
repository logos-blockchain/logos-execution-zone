use nssa_core::program::{
    AccountPostState, ChainedCall, ProgramId, ProgramInput, ProgramOutput, ValidityWindow,
    read_nssa_inputs,
};
use risc0_zkvm::serde::to_vec;

/// A program that sets a validity window on its output and chains to another program with a
/// potentially different validity window.
///
/// Instruction: (`window`, `chained_program_id`, `chained_window`)
/// The initial output uses `window` and chains to `chained_program_id` with `chained_window`.
type Instruction = (ValidityWindow, ProgramId, ValidityWindow);

fn main() {
    let (
        ProgramInput {
            pre_states,
            instruction: (validity_window, chained_program_id, chained_validity_window),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let [pre] = <[_; 1]>::try_from(pre_states.clone()).expect("Expected exactly one pre state");
    let post = pre.account.clone();

    let chained_instruction = to_vec(&chained_validity_window).unwrap();
    let chained_call = ChainedCall {
        program_id: chained_program_id,
        instruction_data: chained_instruction,
        pre_states,
        pda_seeds: vec![],
    };

    ProgramOutput::new(
        instruction_words,
        vec![pre],
        vec![AccountPostState::new(post)],
    )
    .with_validity_window(validity_window)
    .with_chained_calls(vec![chained_call])
    .write();
}
