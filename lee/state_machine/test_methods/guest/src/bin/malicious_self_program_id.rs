use lee_core::program::{
    AccountPostState, DEFAULT_PROGRAM_ID, ProgramInput, ProgramOutput, read_lee_inputs,
};

type Instruction = ();

fn main() {
    let (
        ProgramInput {
            self_account_id: _, // ignore the correct ID
            caller_account_id,
            pre_states,
            instruction: (),
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let post_states = pre_states
        .iter()
        .map(|a| AccountPostState::new(a.account.clone()))
        .collect();

    // Deliberately output wrong self_account_id
    ProgramOutput::new(
        DEFAULT_PROGRAM_ID.into(), // WRONG: should be self_account_id
        caller_account_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .write();
}
