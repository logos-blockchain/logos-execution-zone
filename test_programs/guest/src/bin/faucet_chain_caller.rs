use borsh::to_vec;
use lee_core::{
    account::ProgramShardSelector,
    program::{
        AccountStateDiff, ChainedCall, ProgramCall, ProgramId, ProgramInput, ProgramOutput,
        read_lee_call, respond_unsupported_call,
    },
};

type Instruction = (ProgramId, u128);
// (faucet_program_id, amount)

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (faucet_program_id, amount),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let state_diffs: Vec<_> = pre_states
        .iter()
        .map(|pre| AccountStateDiff::unchanged(pre.clone()))
        .collect();

    assert_eq!(pre_states.len(), 2);

    let chained_calls = vec![ChainedCall {
        program_account_id: faucet_program_id.into(),
        instruction_data: to_vec(&faucet_core::Instruction::GenesisTransfer { amount }).unwrap(),
        shard_selectors: vec![
            ProgramShardSelector::from(&pre_states[0]),
            ProgramShardSelector::from(&pre_states[1]),
        ],
        pda_seeds: vec![],
    }];

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .with_chained_calls(chained_calls)
    .write();
}
