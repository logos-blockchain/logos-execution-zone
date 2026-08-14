use lee_core::program::{AccountPostState, ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = ();

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            ..
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_pre = &pre.account;
    let mut account_post = account_pre.clone();
    account_post.program_owner = [0, 1, 2, 3, 4, 5, 6, 7].into();

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![pre],
        vec![AccountPostState::new(account_post)],
    )
    .write();
}
