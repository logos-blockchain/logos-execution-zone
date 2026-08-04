use lee_core::program::{
    AccountPostState, ChainedCall, InstructionData, ProgramId, ProgramInput, ProgramOutput,
    read_lee_inputs,
};

type Instruction = (ProgramId, InstructionData, bool);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (callee_program_id, callee_instruction, declare_pre_states),
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let (output_pre_states, output_post_states) = if declare_pre_states {
        let post_states = pre_states
            .iter()
            .map(|account| AccountPostState::new(account.account.clone()))
            .collect();
        (pre_states.clone(), post_states)
    } else {
        (Vec::new(), Vec::new())
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        output_pre_states,
        output_post_states,
    )
    .with_chained_calls(vec![ChainedCall {
        program_id: callee_program_id,
        instruction_data: callee_instruction,
        pre_states,
        pda_seeds: vec![],
    }])
    .write();
}
