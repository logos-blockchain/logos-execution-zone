use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, BlockValidityWindow, ProgramCall, ProgramInput, ProgramOutput,
        TimestampValidityWindow, read_lee_call,
    },
};

type Instruction = (BlockValidityWindow, TimestampValidityWindow);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (block_validity_window, timestamp_validity_window),
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "validity_window program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let account_id = pre.account_id;

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
    .with_timestamp_validity_window(timestamp_validity_window)
    .write();
}
