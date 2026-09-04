use lee_core::program::{
    AccountStateDiff, DEFAULT_PROGRAM_ID, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
    respond_unsupported_call,
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
        .map(|a| AccountStateDiff::unchanged(a.clone()))
        .collect();

    // Deliberately output wrong caller_account_id.
    // A real caller_account_id is None for a top-level call, so we spoof Some(DEFAULT_PROGRAM_ID)
    // to simulate a program claiming it was invoked by another program when it was not.
    ProgramOutput::new(
        self_account_id,
        Some(DEFAULT_PROGRAM_ID.into()), // WRONG: should be None for a top-level call
        instruction_data,
        state_diffs,
    )
    .write();
}
