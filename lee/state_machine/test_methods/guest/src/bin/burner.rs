use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

type Instruction = u128;

/// Burns balance out of existence — no corresponding `Add` anywhere in the call, so this is
/// expected to be rejected by the balance-conservation rule
/// (`sum(Add amounts) == sum(Sub amounts)` across the call's diffs), not to succeed.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: balance_to_burn,
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => {
            unreachable!(
                "burner never produces an AccountDiffOutput with diff_data, so its \
                 UpdateFromDiff entrypoint is never invoked"
            )
        }
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let diff = AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Sub(balance_to_burn),
        diff_data: None,
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![AccountDiffOutput::new(diff)],
    )
    .write();
}
