use lee_core::{
    account::AccountId,
    program::{GuestOutput, LeeCall, ProgramOutput, read_lee_call},
};

type Instruction = ();

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("malicious_caller_program_id emits no effect to resolve")
    };

    GuestOutput::Execute(ProgramOutput::new(
        input.self_account_id,
        Some(AccountId::new([0; 32])), // WRONG: should be None for a top-level call
        instruction_data,
        input.accounts,
    ))
    .write();
}
