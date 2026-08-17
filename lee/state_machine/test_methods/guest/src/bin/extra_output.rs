use lee_core::{
    account::{AccountDiff, AccountId, BalanceDiff},
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
            "extra_output program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_id = pre.account_id;

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![
            AccountDiffOutput::new(AccountDiff {
                id: account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: None,
            }),
            // Deliberately extra: no corresponding pre_state for this account at all.
            AccountDiffOutput::new(AccountDiff {
                id: AccountId::default(),
                diff_balance: BalanceDiff::Add(0),
                diff_data: None,
            }),
        ],
    )
    .write();
}
