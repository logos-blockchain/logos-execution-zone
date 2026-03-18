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

    let Ok([sender_pre, receiver_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let mut sender_post = sender_pre.account.clone();
    let mut receiver_post = receiver_pre.account.clone();
    sender_post.balance = sender_post
        .balance
        .checked_sub(balance)
        .expect("Not enough balance to transfer");
    receiver_post.balance = receiver_post
        .balance
        .checked_add(balance)
        .expect("Overflow when adding balance");

    write_nssa_outputs(
        instruction_words,
        vec![sender_pre, receiver_pre],
        vec![
            AccountPostState::new(sender_post),
            AccountPostState::new(receiver_post),
        ],
    );
}
