use lee_core::{
    account::AccountDiff,
    program::{AccountDiffOutput, ProgramCall, read_lee_call},
};

type Instruction = ();

fn main() {
    let ProgramCall::Execute {
        input,
        instruction: (),
    } = read_lee_call::<Instruction>();

    let post_states = input
        .pre_states
        .iter()
        .map(|account| AccountDiffOutput::new(AccountDiff::unchanged(account.account_id)))
        .collect();
    input.into_output(post_states).write();
}
