use lee_core::{
    account::AccountDiff,
    program::{
        AccountDiffOutput, BlockValidityWindow, ProgramCall, TimestampValidityWindow, read_lee_call,
    },
};

type Instruction = (BlockValidityWindow, TimestampValidityWindow);

fn main() {
    let ProgramCall::Execute {
        input,
        instruction: (block_validity_window, timestamp_validity_window),
    } = read_lee_call::<Instruction>();

    let [pre] = input.pre_states.as_slice() else {
        return;
    };

    let diff_output = AccountDiffOutput::new(AccountDiff::unchanged(pre.account_id));

    input
        .into_output(vec![diff_output])
        .with_block_validity_window(block_validity_window)
        .with_timestamp_validity_window(timestamp_validity_window)
        .write();
}
