use nssa_core::program::{AccountPostState, ProgramInput, read_nssa_inputs, write_nssa_outputs};

type Instruction = ();

fn main() {
    let (ProgramInput { pre_states, .. }, instruction_words) = read_nssa_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_pre = &pre.account;
    let mut account_post = account_pre.clone();
    account_post.program_owner = [0, 1, 2, 3, 4, 5, 6, 7];

    write_nssa_outputs(
        instruction_words,
        vec![pre],
        vec![AccountPostState::new(account_post)],
    );
}
