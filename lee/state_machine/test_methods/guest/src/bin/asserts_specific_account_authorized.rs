use lee_core::{
    account::AccountId,
    program::{Plan, ProgramCall, read_program_call},
};

/// Asserts only the named account is authorized, ignoring every other handle it receives.
type Instruction = AccountId;

fn main() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<Instruction>() else {
        panic!("asserts_specific_account_authorized emits no effect to apply")
    };
    let account_to_check = instruction;

    if let Some(account) = input
        .accounts
        .iter()
        .find(|account| account.account_id == account_to_check)
    {
        assert!(
            account.is_authorized,
            "asserts_specific_account_authorized: {account_to_check} is not authorized"
        );
    }

    Plan::new(&input).write();
}
