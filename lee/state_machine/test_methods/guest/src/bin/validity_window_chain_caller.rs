use borsh::to_vec;
use lee_core::{
    account::ProgramShardSelector,
    program::{
        BlockValidityWindow, ChainedCall, LeeCall, Plan, ProgramId, TimestampValidityWindow,
        read_lee_call,
    },
};

/// A program that sets a block validity window on its output and chains to another program with a
/// potentially different block validity window.
///
/// Instruction: (`window`, `chained_program_id`, `chained_window`)
/// The initial output uses `window` and chains to `chained_program_id` with `chained_window`.
/// The chained program (`validity_window`) expects `(BlockValidityWindow, TimestampValidityWindow)`
/// so an unbounded timestamp window is appended automatically.
type Instruction = (BlockValidityWindow, ProgramId, BlockValidityWindow);

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("validity_window_chain_caller emits no effect to resolve")
    };
    let (block_validity_window, chained_program_id, chained_block_validity_window) =
        input.instruction;

    let chained_instruction = to_vec(&(
        chained_block_validity_window,
        TimestampValidityWindow::new_unbounded(),
    ))
    .unwrap();
    let shard_selectors = input
        .accounts
        .iter()
        .map(ProgramShardSelector::from)
        .collect();

    let mut plan = Plan::new(&input, instruction_data);
    plan.block_window(block_validity_window);
    plan.call(ChainedCall {
        program_account_id: chained_program_id.into(),
        instruction_data: chained_instruction,
        shard_selectors,
        pda_seeds: vec![],
    });
    plan.write()
}
