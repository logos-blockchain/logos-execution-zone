use nssa_core::program::{
    AccountPostState, ProgramInput, ProgramOutput, ValidityWindow, read_nssa_inputs,
};

type Instruction = ValidityWindow;

fn main() {
    let (
        ProgramInput {
            pre_states,
            instruction: validity_window,
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let post = pre.account.clone();

    ProgramOutput::new(
        instruction_words,
        vec![pre],
        vec![AccountPostState::new(post)],
    )
    .with_validity_window(validity_window)
    .write();
}
