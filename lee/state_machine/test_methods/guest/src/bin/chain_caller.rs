use lee_core::{
    account::ProgramShardSelector,
    program::{
        ChainedCall, ProgramCall, ProgramInput, ProgramOutput, ShardStateDiff, read_lee_call,
        respond_unsupported_call,
    },
};
use test_guest_core::ChainCall;

/// A program that calls another program `calls` times.
/// It permutes the order of the input accounts on the subsequent call.
fn main() {
    let call = read_lee_call::<ChainCall>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction:
                ChainCall {
                    callee_account_id,
                    instruction_data: call_instruction_data,
                    calls,
                    pda_seed,
                },
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([recipient_pre, sender_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let permuted = vec![
        ProgramShardSelector::from(&sender_pre),
        ProgramShardSelector::from(&recipient_pre),
    ];

    let mut chained_calls = Vec::new();
    for _i in 0..calls {
        let new_chained_call = ChainedCall {
            program_account_id: callee_account_id,
            instruction_data: call_instruction_data.clone(),
            shard_selectors: permuted.clone(),
            pda_seeds: pda_seed.iter().copied().collect(),
        };
        chained_calls.push(new_chained_call);
    }

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![
            ShardStateDiff::unchanged(sender_pre),
            ShardStateDiff::unchanged(recipient_pre),
        ],
    )
    .with_chained_calls(chained_calls)
    .write();
}
