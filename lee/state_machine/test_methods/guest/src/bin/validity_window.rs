use lee_core::program::{
    AccountStateDiff, BlockValidityWindow, ProgramCall, ProgramInput, ProgramOutput,
    TimestampValidityWindow, read_lee_call, respond_unsupported_call,
};

type Instruction = (BlockValidityWindow, TimestampValidityWindow);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (block_validity_window, timestamp_validity_window),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![AccountStateDiff::unchanged(pre)],
    )
    .with_block_validity_window(block_validity_window)
    .with_timestamp_validity_window(timestamp_validity_window)
    .write();
}
