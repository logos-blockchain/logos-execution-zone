use lee_core::{
    account::AccountId,
    program::{GuestOutput, PlanInput, PlanOutput, ProgramCall, read_program_call},
};

type Instruction = ();

fn main() {
    let ProgramCall::Plan(input, ()) = read_program_call::<Instruction>() else {
        panic!("malicious_self_program_id emits no effect to apply")
    };

    GuestOutput::Plan(PlanOutput::new(PlanInput {
        self_account_id: AccountId::new([0; 32]), // WRONG: should be input.self_account_id
        ..input
    }))
    .write();
}
