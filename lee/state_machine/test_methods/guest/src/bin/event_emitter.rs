use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{ChainedCall, InstructionData, LeeCall, Plan, ProgramEvent, read_lee_call},
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct EmitterInstruction {
    pub events: Vec<ProgramEvent>,
    pub chain: Vec<(AccountId, InstructionData)>,
}

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<EmitterInstruction>() else {
        panic!("event_emitter emits no effect to resolve")
    };
    let EmitterInstruction { events, chain } = &input.instruction;

    let shard_selectors: Vec<_> = input
        .accounts
        .iter()
        .map(ProgramShardSelector::from)
        .collect();

    // Emit both the chained calls and a list of events.
    // This is used to test the end-positioning of events in a transaction.
    let mut plan = Plan::new(&input, instruction_data);
    for (program_account_id, call_instruction_data) in chain {
        plan.call(ChainedCall {
            program_account_id: *program_account_id,
            shard_selectors: shard_selectors.clone(),
            instruction_data: call_instruction_data.clone(),
            pda_seeds: vec![],
        });
    }
    for event in events {
        plan.event(event.clone());
    }
    plan.write()
}
