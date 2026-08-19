use lee_core::program::{
    ChainedCall, InstructionData, PdaSeed, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
};
use borsh::to_vec;

type Instruction = (
    Option<PdaSeed>,
    bool,
    ProgramId,
    InstructionData,
    Option<ProgramId>,
);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            mut pre_states,
            instruction: (seed, declare_authorized, callee_program_id, callee_instruction, sibling),
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let Some(first) = pre_states.first_mut() else {
        return;
    };
    first.is_authorized = declare_authorized;

    let sibling_call = sibling.map(|sibling_program_id| {
        let mut sibling_pre = pre_states[0].clone();
        sibling_pre.is_authorized = true;
        ChainedCall {
            program_id: sibling_program_id,
            instruction_data: to_vec(&()).unwrap(),
            pre_states: vec![sibling_pre],
            pda_seeds: vec![],
        }
    });

    let mut chained_calls = vec![ChainedCall {
        program_id: callee_program_id,
        instruction_data: callee_instruction,
        pre_states,
        pda_seeds: seed.into_iter().collect(),
    }];
    chained_calls.extend(sibling_call);

    // Emit an output with only chained calls and no pre or post-states.
    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        Vec::new(),
        Vec::new(),
    )
    .with_chained_calls(chained_calls)
    .write();
}
