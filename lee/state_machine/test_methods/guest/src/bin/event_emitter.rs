use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{
        ChainedCall, InstructionData, ProgramCall, ProgramEvent, ProgramInput, ProgramOutput,
        ShardStateDiff, read_lee_call, respond_unsupported_call,
    },
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct EmitterInstruction {
    pub events: Vec<ProgramEvent>,
    pub chain: Vec<(AccountId, InstructionData)>,
}

fn main() {
    let call = read_lee_call::<EmitterInstruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: EmitterInstruction { events, chain },
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let state_diffs = pre_states
        .iter()
        .map(|account| ShardStateDiff::unchanged(account.clone()))
        .collect();

    let shard_selectors: Vec<_> = pre_states.iter().map(ProgramShardSelector::from).collect();
    let chained_calls = chain
        .into_iter()
        .map(|(program_account_id, call_instruction_data)| ChainedCall {
            program_account_id,
            shard_selectors: shard_selectors.clone(),
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
        state_diffs,
    )
    .with_chained_calls(chained_calls)
    .with_events(events)
    .write();
}
