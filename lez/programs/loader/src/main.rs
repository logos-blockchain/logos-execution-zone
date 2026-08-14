use lee_core::program::{ProgramInput, ProgramOutput, read_lee_inputs};
use loader_core::Instruction;

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
        Instruction::Deploy { bytecode } => {
            loader_core::execute_deploy(self_program_id, pre_states, bytecode)
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
