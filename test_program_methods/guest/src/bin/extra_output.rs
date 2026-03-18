use nssa_core::{
    account::Account,
    program::{AccountPostState, ProgramInput, read_nssa_inputs, write_nssa_outputs},
};

type Instruction = ();

fn main() {
    let (ProgramInput { pre_states, .. }, instruction_words) = read_nssa_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_pre = pre.account.clone();

    write_nssa_outputs(
        instruction_words,
        vec![pre],
        vec![
            AccountPostState::new(account_pre),
            AccountPostState::new(Account::default()),
        ],
    );
}
