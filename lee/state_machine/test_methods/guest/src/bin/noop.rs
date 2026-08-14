use lee_core::program::{AccountPostState, ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = ();

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            ..
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let post_states = pre_states
        .iter()
        .map(|account| AccountPostState::new(account.account.clone()))
        .collect();
    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .write();
}
