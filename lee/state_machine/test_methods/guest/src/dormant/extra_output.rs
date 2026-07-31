use lee_core::{
    account::{AccountDiff, AccountId, BalanceDiff},
    program::{AccountDiffOutput, ProgramInput, ProgramOutput, read_lee_inputs},
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
    ) = read_lee_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let diff = AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Add(0),
        raw_diff: None,
    };
    let extra_diff = AccountDiff {
        id: AccountId::default(),
        diff_balance: BalanceDiff::Add(0),
        raw_diff: None,
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![
            AccountDiffOutput::new(diff),
            AccountDiffOutput::new(extra_diff),
        ],
    )
    .write();
}
