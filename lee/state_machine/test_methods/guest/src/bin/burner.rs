use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

type Instruction = u128;

fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: balance_to_burn,
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    // Clamp to preserve the old saturating_sub semantics (burn at most what's there).
    let burned = balance_to_burn.min(pre.account.balance);
    let diff = AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Sub(burned),
        diff_data: None,
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre],
        vec![AccountDiffOutput::new(diff)],
    )
    .write();
}
