use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};
use pool_stub_program::core::Instruction;

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
        Instruction::InitPool { tick, cardinality } => {
            let [pool] = pre_states
                .try_into()
                .expect("InitPool instruction requires exactly one account");
            pool_stub_program::init::init(pool, tick, cardinality)
        }
        Instruction::Observe { tick } => {
            let [pool, clock] = pre_states
                .try_into()
                .expect("Observe instruction requires exactly two accounts");
            pool_stub_program::observe::observe(pool, clock, tick)
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
