use borsh::to_vec;
use lee_core::{
    account::ProgramShardSelector,
    program::{
        AccountStateDiff, BlockValidityWindow, ChainedCall, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, TimestampValidityWindow, read_lee_call, respond_unsupported_call,
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
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (block_validity_window, chained_program_id, chained_block_validity_window),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let [pre] = <[_; 1]>::try_from(pre_states.clone()).expect("Expected exactly one pre state");

    let chained_instruction = to_vec(&(
        chained_block_validity_window,
        TimestampValidityWindow::new_unbounded(),
    ))
    .unwrap();
    let chained_call = ChainedCall {
        program_account_id: chained_program_id.into(),
        instruction_data: chained_instruction,
        shard_selectors: pre_states.iter().map(ProgramShardSelector::from).collect(),
        pda_seeds: vec![],
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![AccountStateDiff::unchanged(pre)],
    )
    .with_block_validity_window(block_validity_window)
    .with_chained_calls(vec![chained_call])
    .write();
}
