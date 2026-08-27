use lee_core::{
    account::AccountDiff,
    program::{
        AccountDiffOutput, BlockValidityWindow, ProgramCall, ProgramInput, ProgramOutput,
        TimestampValidityWindow, read_lee_call,
    },
};

type Instruction = (BlockValidityWindow, TimestampValidityWindow);

fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (block_validity_window, timestamp_validity_window),
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let diff_output = AccountDiffOutput::new(AccountDiff::unchanged(pre.account_id));

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pre],
        vec![diff_output],
    )
    .with_block_validity_window(block_validity_window)
    .with_timestamp_validity_window(timestamp_validity_window)
    .write();
}
