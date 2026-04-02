use nssa_core::{
    account::Account,
    program::{AccountPostState, ProgramInput, ProgramOutput, read_nssa_inputs},
};

type Instruction = ();

fn main() {
    let (
        ProgramInput {
            self_program_id,
            pre_states,
            ..
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_pre = pre.account.clone();

    ProgramOutput::new(
        self_program_id,
        instruction_words,
        vec![pre],
        vec![
            AccountPostState::new(account_pre),
            AccountPostState::new(Account::default()),
        ],
    )
    .write();
}
