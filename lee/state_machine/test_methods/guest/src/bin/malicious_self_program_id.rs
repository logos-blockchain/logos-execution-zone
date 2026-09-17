use lee_core::{
    account::AccountId,
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

type Instruction = ();

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id: _, // ignore the correct ID
            caller_account_id,
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

    // Deliberately output wrong self_account_id
    ProgramOutput::new(
        AccountId::default(), // WRONG: should be self_account_id
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .write();
}
