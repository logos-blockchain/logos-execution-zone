use lee_core::program::{
    ChainedCall, InstructionData, PdaSeed, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
};

type Instruction = (Option<PdaSeed>, ProgramId, InstructionData);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            mut pre_states,
            instruction: (seed, callee_program_id, callee_instruction),
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let Some(first) = pre_states.first_mut() else {
        return;
    };
    first.is_authorized = true;

    // Emit an output with only chained calls and no pre or post-states.
    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        Vec::new(),
        Vec::new(),
    )
    .with_chained_calls(vec![ChainedCall {
        program_id: callee_program_id,
        instruction_data: callee_instruction,
        pre_states,
        pda_seeds: seed.into_iter().collect(),
    }])
    .write();
}
