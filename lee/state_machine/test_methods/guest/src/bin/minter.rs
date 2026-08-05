use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

type Instruction = ();

/// Mints one unit of native balance out of nothing — no corresponding `Sub` anywhere in the
/// call, so this is expected to be rejected by the balance-conservation rule
/// (`sum(Add amounts) == sum(Sub amounts)` across the call's diffs), not to succeed.
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
        ProgramCall::UpdateFromDiff { .. } => {
            unreachable!(
                "minter never produces an AccountDiffOutput with diff_data, so its \
                 UpdateFromDiff entrypoint is never invoked"
            )
        }
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let diff = AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Add(1),
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
