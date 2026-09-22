use lee_core::{
    account::ProgramShardSelector,
    program::{ChainedCall, LeeCall, Plan, ProgramId, read_lee_call},
};

type Instruction = (ProgramId, u128);
// (faucet_program_id, amount)

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("faucet_chain_caller emits no effect to resolve")
    };
    let (faucet_program_id, amount) = input.instruction;

    let Ok([faucet, recipient]) = <[_; 2]>::try_from(input.accounts.clone()) else {
        panic!("Expected exactly 2 input accounts: faucet PDA, recipient");
    };

    let mut plan = Plan::new(&input, instruction_data);
    plan.call(ChainedCall::new(
        faucet_program_id.into(),
        vec![
            ProgramShardSelector::from(&faucet),
            ProgramShardSelector::from(&recipient),
        ],
        &faucet_core::Instruction::GenesisTransfer { amount },
    ));
    plan.write()
}
