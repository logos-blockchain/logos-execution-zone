use lee_core::program::{AccountPostState, ProgramInput, ProgramOutput, read_lee_inputs};

type Instruction = ();

/// Silently drops the second account entirely from its own output: given two `pre_states`, it
/// returns only one `(pre, post)` pair, echoing the first account back unchanged.
///
/// Differs from `missing_output` because the `pre_state` and `post_states` lengths match. We
/// simply drop the account from both before returning them as part of the program's output.
fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            ..
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pre1, _pre2]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let account_pre1 = pre1.account.clone();

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![pre1],
        vec![AccountPostState::new(account_pre1)],
    )
    .write();
}
