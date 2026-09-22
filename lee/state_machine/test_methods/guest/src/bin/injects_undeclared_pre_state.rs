use lee_core::{
    account::AccountId,
    program::{AccountMeta, GuestOutput, LeeCall, ProgramOutput, read_lee_call},
};

/// Echoes its handles and adds one it was never given. Hand-rolls its output because `Plan`
/// copies the handle echo straight out of the input.
type Instruction = AccountId;

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("injects_undeclared_pre_state emits no effect to resolve")
    };

    let mut accounts = input.accounts;
    accounts.push(AccountMeta::balance(input.instruction, false));

    GuestOutput::Execute(ProgramOutput::new(
        input.self_account_id,
        input.caller_account_id,
        instruction_data,
        accounts,
    ))
    .write();
}
