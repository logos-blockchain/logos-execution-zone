use lee_core::program::{
    AccountStateDiff, DEFAULT_PROGRAM_ID, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
    respond_unsupported_call,
};

type Instruction = ();

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id: _, // ignore the correct ID
            caller_program_id,
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

    // Deliberately output wrong self_program_id
    ProgramOutput::new(
        DEFAULT_PROGRAM_ID, // WRONG: should be self_program_id
        caller_program_id,
        instruction_data,
        state_diffs,
    )
    .write();
}
