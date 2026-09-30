use lee_core::{
    BlockId, Timestamp,
    account::ProgramShardSelector,
    program::{ChainedCall, Plan, ProgramCall, read_program_call},
};

type Instruction = (Timestamp, BlockId);

/// A program that chain-calls the clock program with the clock accounts it received.
/// Used in tests to verify that user transactions cannot modify clock accounts, even indirectly
/// via chain calls.
fn main() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<Instruction>() else {
        panic!("clock_chain_caller emits no effect to apply")
    };
    let (timestamp, block_id) = instruction;

    let mut plan = Plan::new(&input);
    plan.call(ChainedCall::new(
        clock_core::clock_account_id(),
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
