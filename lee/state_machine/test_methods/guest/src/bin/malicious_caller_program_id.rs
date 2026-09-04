use lee_core::{
    account::AccountId,
    program::{
        ProgramCall, ProgramInput, ProgramOutput, ShardStateDiff, read_lee_call,
        respond_unsupported_call,
    },
};

type Instruction = ();

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id: _, // ignore the actual caller
            pre_states,
            instruction: (),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let state_diffs = pre_states
        .iter()
        .map(|a| ShardStateDiff::unchanged(a.clone()))
        .collect();

    // Deliberately output wrong caller_account_id.
    // A real caller_account_id is None for a top-level call, so we spoof the zero address
    // to simulate a program claiming it was invoked by another program when it was not.
    ProgramOutput::new(
        self_account_id,
        Some(AccountId::new([0; 32])), // WRONG: should be None for a top-level call
        instruction_data,
        state_diffs,
    )
    .write();
}
