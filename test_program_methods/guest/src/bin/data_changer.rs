#![expect(clippy::manual_let_else, reason = "Looks much better")]

use nssa_core::program::{AccountPostState, ProgramInput, read_nssa_inputs, write_nssa_outputs};

type Instruction = Vec<u8>;

/// A program that modifies the account data by setting bytes sent in instruction.
fn main() {
    let (
        ProgramInput {
            pre_states,
            instruction: data,
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let [pre] = match pre_states.try_into() {
        Ok(array) => array,
        Err(_) => return,
    };

    let account_pre = &pre.account;
    let mut account_post = account_pre.clone();
    account_post.data = data
        .try_into()
        .expect("provided data should fit into data limit");

    write_nssa_outputs(
        instruction_words,
        vec![pre],
        vec![AccountPostState::new_claimed(account_post)],
    );
}
