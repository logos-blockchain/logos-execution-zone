use lee_core::program::{
    ProgramCall, ProgramInput, ProgramOutput, ShardStateDiff, read_lee_call,
    respond_unsupported_call,
};

type Instruction = ();

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            ..
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let state_diffs = pre_states
        .iter()
        .map(|account| ShardStateDiff::unchanged(account.clone()))
        .collect();
    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .write();
}
