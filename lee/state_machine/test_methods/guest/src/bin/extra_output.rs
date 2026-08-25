use lee_core::{
    account::{AccountDiff, AccountId},
    program::{AccountDiffOutput, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

type Instruction = ();

fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            ..
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_id = pre.account_id;

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre],
        vec![
            AccountDiffOutput::new(AccountDiff::unchanged(account_id)),
            // Extra, undeclared output: no matching pre-state for this account at all.
            AccountDiffOutput::new(AccountDiff::unchanged(AccountId::default())),
        ],
    )
    .write();
}
