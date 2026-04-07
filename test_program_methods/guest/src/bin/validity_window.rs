use nssa_core::program::{
    AccountPostState, BlockValidityWindow, ProgramInput, ProgramOutput, TimestampValidityWindow,
    read_nssa_inputs,
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
    ) = read_nssa_inputs::<Instruction>();

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let post = pre.account.clone();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pre],
        vec![AccountPostState::new(post)],
    )
    .with_block_validity_window(block_validity_window)
    .with_timestamp_validity_window(timestamp_validity_window)
    .write();
}
