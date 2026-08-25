use borsh::to_vec;
use lee_core::program::{
    ChainedCall, InstructionData, PdaSeed, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
};

type Instruction = (
    PdaSeed,
    ProgramId,
    InstructionData,
    Option<(ProgramId, Option<bool>)>,
);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (delegated_seed, callee_program_id, callee_instruction, sibling),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Some((pda, rest)) = pre_states.split_first() else {
        return;
    };

    let pda_for_callee = |is_authorized| {
        let mut for_callee = pda.clone();
        for_callee.is_authorized = is_authorized;
        for_callee
    };

    // Send a call to the specified program with the same pre-states
    // but authorized first PDA supplied.
    // Push all the delegated seeds.
    let mut chained_calls = vec![ChainedCall {
        program_id: callee_program_id,
        instruction_data: callee_instruction,
        pre_states: std::iter::once(pda_for_callee(true))
            .chain(rest.iter().cloned())
            .collect(),
        pda_seeds: vec![delegated_seed],
    }];

    // If sibling is present in instruction, send out a call
    // with no seeds so that PDAs stay unauthorized in parallel
    // branches.
    if let Some((sibling_program_id, sibling_pda)) = sibling {
        chained_calls.push(ChainedCall {
            program_id: sibling_program_id,
            instruction_data: to_vec(&()).unwrap(),
            pre_states: sibling_pda.map_or_else(
                || rest.to_vec(),
                |is_authorized| {
                    std::iter::once(pda_for_callee(is_authorized))
                        .chain(rest.iter().cloned())
                        .collect()
                },
            ),
            pda_seeds: vec![],
        });
    }

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![pda.clone()],
        vec![pda.account.clone()],
    )
    .with_chained_calls(chained_calls)
    .write();
}
