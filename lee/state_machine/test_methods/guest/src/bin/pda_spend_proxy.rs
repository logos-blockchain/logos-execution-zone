use lee_core::{
    native_token::custody_transfer,
    program::{LeeCall, PdaSeed, Plan, read_lee_call},
};

/// Proxy for spending from a private PDA via the native token program.
///
/// `accounts = [pda, recipient]`. Debits the PDA and credits the recipient.
/// The PDA-to-npk binding is established via `pda_seeds` in the chained transfer.
type Instruction = (PdaSeed, u128);

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("pda_spend_proxy emits no effect to resolve")
    };
    let (seed, amount) = input.instruction;

    let Ok([first, second]) = <[_; 2]>::try_from(input.accounts.clone()) else {
        return;
    };

    let mut plan = Plan::new(&input, instruction_data);
    plan.call(custody_transfer(
        first.account_id,
        seed,
        second.account_id,
        amount,
    ));
    plan.write()
}
