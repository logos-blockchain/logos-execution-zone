use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = u128;

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: balance,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    if let Ok([account_pre]) = <[_; 1]>::try_from(pre_states.clone()) {
        let account_post = account_pre.account;

        ProgramOutput::new(
            self_program_id,
            caller_program_id,
            instruction_data,
            pre_states,
            vec![account_post],
        )
        .write();
        return;
    }

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

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![sender_pre, receiver_pre],
        vec![sender_post, receiver_post],
    )
    .write();
}
