use lee_core::program::{ProgramId, ProgramInput, ProgramOutput, read_lee_inputs};
use loader_core::Instruction;

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let self_program_id = ProgramId::from(self_account_id);
    let pre_states_clone = pre_states.clone();

    let post_states = match instruction {
        Instruction::Deploy { bytecode } => {
            loader_core::execute_deploy(self_program_id, pre_states, bytecode)
        }
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_words,
        pre_states_clone,
        post_states,
    )
    .write();
}
