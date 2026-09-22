use lee_core::{
    account::AccountId,
    program::{GuestOutput, LeeCall, ProgramOutput, read_lee_call},
};

type Instruction = ();

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("malicious_self_program_id emits no effect to resolve")
    };

    GuestOutput::Execute(ProgramOutput::new(
        AccountId::new([0; 32]), // WRONG: should be input.self_account_id
        input.caller_account_id,
        instruction_data,
        input.accounts,
    ))
    .write();
}
