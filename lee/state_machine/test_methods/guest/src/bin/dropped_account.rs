use lee_core::{
    account::AccountDiff,
    program::{AccountDiffOutput, ProgramCall, ProgramInput, ProgramOutput, read_lee_call},
};

type Instruction = ();

/// Silently drops the second account entirely from its own output: given two `pre_states`, it
/// returns only one `(pre, post)` pair, echoing the first account back unchanged.
///
/// Differs from `missing_output` because the `pre_state` and `post_states` lengths match. We
/// simply drop the account from both before returning them as part of the program's output.
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

    let Ok([pre1, _pre2]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let account_id1 = pre1.account_id;

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre1],
        vec![AccountDiffOutput::new(AccountDiff::unchanged(account_id1))],
    )
    .write();
}
