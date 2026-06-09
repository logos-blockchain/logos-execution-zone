use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};
use twap_program::core::Instruction;

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let pre_states_clone = pre_states.clone();

    let post_states = match instruction {
        Instruction::ReadTwap {
            window_blocks,
            max_age_blocks,
        } => {
            let [pool, clock, price] = pre_states
                .try_into()
                .expect("ReadTwap instruction requires exactly three accounts");
            twap_program::read_twap::read_twap(pool, clock, price, window_blocks, max_age_blocks)
        }
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        pre_states_clone,
        post_states,
    )
    .write();
}
