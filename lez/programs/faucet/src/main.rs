use faucet_core::Instruction;
use lee_core::{
    native_token::custody_transfer,
    program::{LeeCall, Plan, read_lee_call},
};

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("Faucet emits no effect to resolve");
    };
    let Instruction::GenesisTransfer { amount } = &input.instruction;

    assert!(
        input.caller_account_id.is_none(),
        "Faucet cannot be invoked through chain calls"
    );

    let [faucet, recipient] = <[_; 2]>::try_from(input.accounts.clone())
        .expect("GenesisTransfer requires exactly 2 accounts");

    assert_eq!(
        faucet.account_id,
        faucet_core::compute_faucet_account_id(input.self_account_id),
        "First account must be faucet PDA"
    );

    let mut plan = Plan::new(&input, instruction_data);
    plan.call(custody_transfer(
        faucet.account_id,
        faucet_core::compute_faucet_seed(),
        recipient.account_id,
        *amount,
    ));
    plan.write()
}
