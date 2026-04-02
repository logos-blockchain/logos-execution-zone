use nssa_core::program::{AccountPostState, ProgramInput, ProgramOutput, read_nssa_inputs};

type Instruction = ();

fn main() {
    let (
        ProgramInput {
            self_program_id,
            pre_states,
            ..
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let post_states = pre_states
        .iter()
        .map(|account| AccountPostState::new(account.account.clone()))
        .collect();
    ProgramOutput::new(self_program_id, instruction_words, pre_states, post_states).write();
}
