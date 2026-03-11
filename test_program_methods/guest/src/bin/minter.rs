#![expect(clippy::manual_let_else, reason = "Looks much better")]

use nssa_core::program::{AccountPostState, ProgramInput, read_nssa_inputs, write_nssa_outputs};

type Instruction = ();

fn main() {
    let (ProgramInput { pre_states, .. }, instruction_words) = read_nssa_inputs::<Instruction>();

    let [pre] = match pre_states.try_into() {
        Ok(array) => array,
        Err(_) => return,
    };

    let account_pre = &pre.account;
    let mut account_post = account_pre.clone();
    account_post.balance = account_post
        .balance
        .checked_add(1)
        .expect("Balance overflow");

    write_nssa_outputs(
        instruction_words,
        vec![pre],
        vec![AccountPostState::new(account_post)],
    );
}
