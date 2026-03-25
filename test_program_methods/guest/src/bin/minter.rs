use nssa_core::program::{AccountPostState, ProgramInput, ProgramOutput, read_nssa_inputs};

type Instruction = ();

fn main() {
    let (ProgramInput { pre_states, .. }, instruction_words) = read_nssa_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_pre = &pre.account;
    let mut account_post = account_pre.clone();
    account_post.balance = account_post
        .balance
        .checked_add(1)
        .expect("Balance overflow");

    ProgramOutput::new(instruction_words, vec![pre], vec![AccountPostState::new(account_post)])
        .write();
}
