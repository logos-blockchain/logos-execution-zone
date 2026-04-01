use nssa_core::program::{
    AccountPostState, BlockValidityWindow, ChainedCall, ProgramId, ProgramInput, ProgramOutput,
    TimestampValidityWindow, read_nssa_inputs,
};
use risc0_zkvm::serde::to_vec;

/// A program that sets a block validity window on its output and chains to another program with a
/// potentially different block validity window.
///
/// Instruction: (`window`, `chained_program_id`, `chained_window`)
/// The initial output uses `window` and chains to `chained_program_id` with `chained_window`.
/// The chained program (`validity_window`) expects `(BlockValidityWindow, TimestampValidityWindow)`
/// so an unbounded timestamp window is appended automatically.
type Instruction = (BlockValidityWindow, ProgramId, BlockValidityWindow);

fn main() {
    let (
        ProgramInput { self_program_id,
            pre_states,
            instruction: (block_validity_window, chained_program_id, chained_block_validity_window),
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let [pre] = <[_; 1]>::try_from(pre_states.clone()).expect("Expected exactly one pre state");
    let post = pre.account.clone();

    let chained_instruction = to_vec(&(
        chained_block_validity_window,
        TimestampValidityWindow::new_unbounded(),
    ))
    .unwrap();
    let chained_call = ChainedCall {
        program_id: chained_program_id,
        instruction_data: chained_instruction,
        pre_states,
        pda_seeds: vec![],
    };

    ProgramOutput::new(
        self_program_id,
        instruction_words,
        vec![pre],
        vec![AccountPostState::new(post)],
    )
    .with_block_validity_window(block_validity_window)
    .with_chained_calls(vec![chained_call])
    .write();
}
