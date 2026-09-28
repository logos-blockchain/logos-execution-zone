use lee_core::{
    account::AccountId,
    program::{GuestOutput, PlanInput, PlanOutput, ProgramCall, read_program_call},
};

type Instruction = ();

fn main() {
    let ProgramCall::Plan(input, ()) = read_program_call::<Instruction>() else {
        panic!("malicious_caller_program_id emits no effect to apply")
    };

    GuestOutput::Plan(PlanOutput::new(PlanInput {
        // WRONG: should be None for a top-level call
        caller_account_id: Some(AccountId::new([0; 32])),
        ..input
    }))
    .write();
}
