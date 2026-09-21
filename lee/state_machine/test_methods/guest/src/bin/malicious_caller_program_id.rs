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

    ProgramOutput::new(
        self_account_id,
        Some(AccountId::new([0; 32])), // WRONG: should be None for a top-level call
        instruction_data,
        state_diffs,
    )
    .write();
}
