use lee_core::program::{LeeCall, Plan, read_lee_call};

/// A variant of `noop` that asserts every handle it is given is authorized. Any unauthorized
/// handle panics the guest, failing the whole circuit proof. Used as a callee in private-PDA
/// delegation tests to actually exercise the authorization propagated through
/// `ChainedCall.pda_seeds`.
type Instruction = ();

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("auth_asserting_noop emits no effect to resolve")
    };

    for account in &input.accounts {
        assert!(
            account.is_authorized,
            "auth_asserting_noop: {} is not authorized",
            account.account_id
        );
    }

    Plan::new(&input, instruction_data).write();
}
