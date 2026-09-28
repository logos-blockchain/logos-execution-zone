use lee_core::{
    account::AccountId,
    program::{AccountMeta, GuestOutput, PlanInput, PlanOutput, ProgramCall, read_program_call},
};

/// Echoes its handles and adds one it was never given.
type Instruction = AccountId;

fn main() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<Instruction>() else {
        panic!("injects_undeclared_pre_state emits no effect to apply")
    };

    let mut accounts = input.accounts;
    accounts.push(AccountMeta::native_balance(instruction, false));

    GuestOutput::Plan(PlanOutput::new(PlanInput { accounts, ..input })).write();
}
