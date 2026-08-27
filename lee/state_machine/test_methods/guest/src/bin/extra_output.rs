use lee_core::{
    account::{AccountDiff, AccountId},
    program::{AccountDiffOutput, ProgramCall, read_lee_call},
};

type Instruction = ();

fn main() {
    let ProgramCall::Execute {
        input,
        instruction: (),
    } = read_lee_call::<Instruction>();

    let [pre] = input.pre_states.as_slice() else {
        return;
    };

    let account_id = pre.account_id;

    input
        .into_output(vec![
            AccountDiffOutput::new(AccountDiff::unchanged(account_id)),
            // Extra, undeclared output: no matching pre-state for this account at all.
            AccountDiffOutput::new(AccountDiff::unchanged(AccountId::default())),
        ])
        .write();
}
