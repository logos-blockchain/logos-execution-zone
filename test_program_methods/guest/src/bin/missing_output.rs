use nssa_core::program::{AccountPostState, ProgramInput, read_nssa_inputs, write_nssa_outputs};

type Instruction = ();

fn main() {
    let (ProgramInput { pre_states, .. }, instruction_words) = read_nssa_inputs::<Instruction>();

    let Ok([pre1, pre2]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let account_pre1 = pre1.account.clone();

    write_nssa_outputs(
        instruction_words,
        vec![pre1, pre2],
        vec![AccountPostState::new(account_pre1)],
    );
}
