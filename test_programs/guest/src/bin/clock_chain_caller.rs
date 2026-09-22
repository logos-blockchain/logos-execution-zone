use lee_core::{
    BlockId, Timestamp,
    account::ProgramShardSelector,
    program::{ChainedCall, LeeCall, Plan, ProgramId, read_lee_call},
};

type Instruction = (ProgramId, Timestamp, BlockId);

/// A program that chain-calls the clock program with the clock accounts it received.
/// Used in tests to verify that user transactions cannot modify clock accounts, even indirectly
/// via chain calls.
fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("clock_chain_caller emits no effect to resolve")
    };
    let (clock_program_id, timestamp, block_id) = input.instruction;

    let mut plan = Plan::new(&input, instruction_data);
    plan.call(ChainedCall::new(
        clock_program_id.into(),
        input
            .accounts
            .iter()
            .map(ProgramShardSelector::from)
            .collect(),
        &clock_core::Instruction {
            timestamp,
            block_id,
        },
    ));
    plan.write()
}
