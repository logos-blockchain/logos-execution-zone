use nssa_core::program::{AccountPostState, ProgramInput, ProgramOutput, read_nssa_inputs};

type Instruction = u128;

fn main() {
    let (
        ProgramInput {
            self_program_id,
            pre_states,
            instruction: balance_to_burn,
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_pre = &pre.account;
    let mut account_post = account_pre.clone();
    account_post.balance = account_post.balance.saturating_sub(balance_to_burn);

    ProgramOutput::new(
        self_program_id,
        instruction_words,
        vec![pre],
        vec![AccountPostState::new(account_post)],
    )
    .write();
}
