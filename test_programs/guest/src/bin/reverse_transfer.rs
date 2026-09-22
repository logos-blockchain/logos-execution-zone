use lee_core::{
    account::ProgramShardSelector,
    native_token::{Instruction as NativeInstruction, NATIVE_TOKEN_PROGRAM_ID},
    program::{ChainedCall, LeeCall, Plan, read_lee_call},
};

type Instruction = u128;

/// Moves balance out of the SECOND account into the first — the direction a
/// callee handed someone else's account would take to help itself.
fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("reverse_transfer emits no effect to resolve")
    };
    let amount = input.instruction;

    let Ok([recipient, source]) = <[_; 2]>::try_from(input.accounts.clone()) else {
        return;
    };

    let mut plan = Plan::new(&input, instruction_data);
    plan.call(ChainedCall::new(
        NATIVE_TOKEN_PROGRAM_ID,
        vec![
            ProgramShardSelector::from(&source),
            ProgramShardSelector::from(&recipient),
        ],
        &NativeInstruction::Transfer { amount },
    ));
    plan.write()
}
