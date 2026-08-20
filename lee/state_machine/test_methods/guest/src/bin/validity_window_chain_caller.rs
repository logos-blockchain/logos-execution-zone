use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, BlockValidityWindow, ChainedCall, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, TimestampValidityWindow, read_lee_call,
    },
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
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (block_validity_window, chained_program_id, chained_block_validity_window),
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "validity_window_chain_caller program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    let [pre] = <[_; 1]>::try_from(pre_states).expect("Expected exactly one pre state");
    let account_id = pre.account_id;

    let chained_instruction = to_vec(&(
        chained_block_validity_window,
        TimestampValidityWindow::new_unbounded(),
    ))
    .unwrap();
    let chained_call = ChainedCall {
        program_id: chained_program_id,
        instruction_data: chained_instruction,
        pre_state_refs: vec![account_id],
        pda_seeds: vec![],
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![AccountDiffOutput::new(AccountDiff {
            id: account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: None,
        })],
    )
    .with_block_validity_window(block_validity_window)
    .with_chained_calls(vec![chained_call])
    .write();
}
