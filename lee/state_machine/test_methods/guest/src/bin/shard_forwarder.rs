use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{
        ChainedCall, InstructionData, ProgramCall, ProgramInput, ProgramOutput, ShardStateDiff,
        read_lee_call, respond_unsupported_call,
    },
};

type Instruction = Vec<(AccountId, ProgramShardSelector, InstructionData)>;

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: callees,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([own]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let state_diffs = vec![ShardStateDiff::unchanged(own)];

    let chained_calls = callees
        .into_iter()
        .map(|(callee, shard_selector, callee_instruction)| ChainedCall {
            program_account_id: callee,
            instruction_data: callee_instruction,
            shard_selectors: vec![shard_selector],
            pda_seeds: vec![],
        })
        .collect();

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .with_chained_calls(chained_calls)
    .write();
}
