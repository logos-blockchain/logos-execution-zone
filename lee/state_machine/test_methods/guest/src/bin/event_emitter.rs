use lee_core::program::{
    AccountPostState, ChainedCall, InstructionData, ProgramEvent, ProgramId, ProgramInput,
    ProgramOutput, read_lee_inputs,
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct EmitterInstruction {
    pub events: Vec<ProgramEvent>,
    pub chain: Vec<(ProgramId, InstructionData)>,
}

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: EmitterInstruction { events, chain },
        },
        instruction_data,
    ) = read_lee_inputs::<EmitterInstruction>();

    let post_states = pre_states
        .iter()
        .map(|account| AccountPostState::new(account.account.clone()))
        .collect();

    let pre_state_ids: Vec<_> = pre_states.iter().map(|pre| pre.account_id).collect();
    let chained_calls = chain
        .into_iter()
        .map(|(program_id, call_instruction_data)| ChainedCall {
            program_account_id: program_id.into(),
            pre_state_ids: pre_state_ids.clone(),
            instruction_data: call_instruction_data,
            pda_seeds: vec![],
        })
        .collect();

    // Emit both the chained calls and a list of events.
    // This is used to test the end-positioning of events in a transaction.
    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .with_chained_calls(chained_calls)
    .with_events(events)
    .write();
}
