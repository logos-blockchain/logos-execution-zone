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
        ProgramCall::UpdateFromDiff { .. } => {
            unreachable!(
                "validity_window never produces an AccountDiffOutput with diff_data, so its \
                 UpdateFromDiff entrypoint is never invoked"
            )
        }
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let diff = AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![AccountDiffOutput::new(diff)],
    )
    .with_block_validity_window(block_validity_window)
    .with_timestamp_validity_window(timestamp_validity_window)
    .write();
}
