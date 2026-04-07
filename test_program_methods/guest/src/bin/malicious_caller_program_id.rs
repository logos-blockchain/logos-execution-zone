use nssa_core::program::{
    AccountPostState, DEFAULT_PROGRAM_ID, ProgramInput, ProgramOutput, read_nssa_inputs,
};

type Instruction = ();

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id: _, // ignore the actual caller
            pre_states,
            instruction: (),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let post_states = pre_states
        .iter()
        .map(|a| AccountPostState::new(a.account.clone()))
        .collect();

    // Deliberately output wrong caller_program_id.
    // A real caller_program_id is None for a top-level call, so we spoof Some(DEFAULT_PROGRAM_ID)
    // to simulate a program claiming it was invoked by another program when it was not.
    ProgramOutput::new(
        self_program_id,
        Some(DEFAULT_PROGRAM_ID), // WRONG: should be None for a top-level call
        instruction_words,
        pre_states,
        post_states,
    )
    .write();
}
