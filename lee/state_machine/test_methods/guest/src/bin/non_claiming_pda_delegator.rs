use lee_core::program::{
    AccountPostState, ChainedCall, InstructionData, PdaSeed, ProgramId, ProgramInput,
    ProgramOutput, read_lee_inputs,
};
use risc0_zkvm::serde::to_vec;

type Instruction = (PdaSeed, ProgramId, ProgramId, InstructionData);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction:
                (delegated_seed, delegatee_program_id, claimer_program_id, claimer_instruction),
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let Ok([pda]) = <[_; 1]>::try_from(pre_states.clone()) else {
        return;
    };

    let mut delegated = pda.clone();
    delegated.is_authorized = true;

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        pre_states,
        vec![AccountPostState::new(pda.account.clone())],
    )
    .with_chained_calls(vec![
        ChainedCall {
            program_id: delegatee_program_id,
            instruction_data: to_vec(&()).unwrap(),
            pre_states: vec![delegated],
            pda_seeds: vec![delegated_seed],
        },
        ChainedCall {
            program_id: claimer_program_id,
            instruction_data: claimer_instruction,
            pre_states: vec![pda],
            pda_seeds: vec![],
        },
    ])
    .write();
}
