use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

type Instruction = ();

/// Silently drops the second account entirely from its own output: given two `pre_states`, it
/// returns only one `(pre, post)` pair, echoing the first account back unchanged.
///
/// Differs from `missing_output` because the `pre_state` and `post_states` lengths match. We
/// simply drop the account from both before returning them as part of the program's output.
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
            "dropped_account program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    let Ok([pre1, _pre2]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let account_id = pre1.account_id;

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre1],
        vec![AccountDiffOutput::new(AccountDiff {
            id: account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: None,
        })],
    )
    .write();
}
