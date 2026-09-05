use lee_core::{
    account::{AccountId, Input},
    program::{
        ProgramCall, ProgramInput, ProgramOutput, ShardStateDiff, read_lee_call,
        respond_unsupported_call,
    },
};

/// Echoes its real `pre_states` unchanged, then appends one fabricated, untouched account never
/// present in its own input — to test whether reporting it in `ProgramOutput.state_diffs` alone
/// is enough to get it resolved, independent of `ChainedCall.positions`.
type Instruction = AccountId;

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: fabricated_account_id,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let mut state_diffs: Vec<ShardStateDiff> = pre_states
        .into_iter()
        .map(ShardStateDiff::unchanged)
        .collect();

    state_diffs.push(ShardStateDiff::unchanged(Input::balance_only(
        fabricated_account_id,
        false,
        0,
    )));

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .write();
}
