use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

type Instruction = ();

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            ..
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "missing_output program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    let Ok([pre1, pre2]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let post1 = AccountDiffOutput::new(AccountDiff {
        id: pre1.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    });

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre1, pre2],
        vec![post1],
    )
    .write();
}
