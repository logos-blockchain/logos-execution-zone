use lee_core::{
    account::AccountId,
    program::{
        AccountInput, ProgramCall, ProgramInput, ProgramOutput, ShardStateDiff, read_lee_call,
        respond_unsupported_call,
    },
};

/// Echoes its inputs unchanged and adds an account that was not supplied.
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

    state_diffs.push(ShardStateDiff::unchanged(AccountInput::balance(
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
