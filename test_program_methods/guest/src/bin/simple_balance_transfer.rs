#![expect(clippy::manual_let_else, reason = "Looks much better")]

use nssa_core::program::{AccountPostState, ProgramInput, read_nssa_inputs, write_nssa_outputs};

type Instruction = u128;

fn main() {
    let (
        ProgramInput {
            pre_states,
            instruction: balance,
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let [sender_pre, receiver_pre] = match pre_states.try_into() {
        Ok(array) => array,
        Err(_) => return,
    };

    let mut sender_post = sender_pre.account.clone();
    let mut receiver_post = receiver_pre.account.clone();
    sender_post.balance -= balance;
    receiver_post.balance += balance;

    write_nssa_outputs(
        instruction_words,
        vec![sender_pre, receiver_pre],
        vec![
            AccountPostState::new(sender_post),
            AccountPostState::new(receiver_post),
        ],
    );
}
