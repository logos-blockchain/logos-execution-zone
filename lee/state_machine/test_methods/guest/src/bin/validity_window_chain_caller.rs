use borsh::to_vec;
use lee_core::program::{
    AccountDiffOutput, BlockValidityWindow, ChainedCall, ProgramCall, ProgramId,
    TimestampValidityWindow, read_lee_call,
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
    let ProgramCall::Execute {
        input,
        instruction: (block_validity_window, chained_program_id, chained_block_validity_window),
    } = read_lee_call::<Instruction>();

    let [pre] = input.pre_states.as_slice() else {
        panic!("Expected exactly one pre state");
    };
    let account_id = pre.account_id;

    let chained_instruction = to_vec(&(
        chained_block_validity_window,
        TimestampValidityWindow::new_unbounded(),
    ))
    .unwrap();
    let chained_call = ChainedCall {
        program_id: chained_program_id,
        instruction_data: chained_instruction,
        accounts: vec![account_id],
        pda_seeds: vec![],
    };

    input
        .into_output(vec![AccountDiffOutput::unchanged(account_id)])
        .with_block_validity_window(block_validity_window)
        .with_chained_calls(vec![chained_call])
        .write();
}
