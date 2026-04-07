use nssa_core::program::{
    AccountPostState, DEFAULT_PROGRAM_ID, ProgramInput, ProgramOutput, read_nssa_inputs,
};

type Instruction = ();

fn main() {
    let (
        ProgramInput {
            self_program_id: _, // ignore the correct ID
            caller_program_id,
            pre_states,
            instruction: (),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let post_states = pre_states
        .iter()
        .map(|a| AccountPostState::new(a.account.clone()))
        .collect();

    // Deliberately output wrong self_program_id
    ProgramOutput::new(
        DEFAULT_PROGRAM_ID, // WRONG: should be self_program_id
        caller_program_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .write();
}
