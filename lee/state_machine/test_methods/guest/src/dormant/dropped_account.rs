use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, ProgramInput, ProgramOutput, read_lee_inputs},
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
    ) = read_lee_inputs::<Instruction>();

    let Ok([pre1, _pre2]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let diff = AccountDiff {
        id: pre1.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre1],
        vec![AccountDiffOutput::new(diff)],
    )
    .write();
}
