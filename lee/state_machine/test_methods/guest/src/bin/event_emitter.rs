use lee_core::program::{
    AccountPostState, ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EmitterInstruction {
    pub events: Vec<Vec<u8>>,
    pub chain: Vec<(ProgramId, Vec<u32>)>,
}

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: EmitterInstruction { events, chain },
        },
        instruction_words,
    ) = read_lee_inputs::<EmitterInstruction>();

    let post_states = pre_states
        .iter()
        .map(|account| AccountPostState::new(account.account.clone()))
        .collect();

    let chained_calls = chain
        .into_iter()
        .map(|(program_id, instruction_data)| ChainedCall {
            program_id,
            pre_states: pre_states.clone(),
            instruction_data,
            pda_seeds: vec![],
        })
        .collect();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .with_chained_calls(chained_calls)
    .with_events(events)
    .write();
}
