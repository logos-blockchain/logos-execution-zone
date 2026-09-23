//! Guest bodies shared by both test-guest crates, so the same fixture behaviour cannot drift
//! between them. Each crate still ships its own binary, and so its own image id.

use lee_core::{
    native_token::custody_transfer,
    program::{
        ChainedCall, PdaSeed, ProgramCall, ProgramInput, ProgramOutput, ShardStateDiff,
        read_lee_call, respond_unsupported_call,
    },
};

use crate::ChainCall;

/// Calls another program `calls` times, permuting the input account order on each call.
pub fn chain_caller() {
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
        lee_core::account::ProgramShardSelector::from(&sender_pre),
        lee_core::account::ProgramShardSelector::from(&recipient_pre),
    ];

    let mut chained_calls = Vec::new();
    for _ in 0..calls {
        chained_calls.push(ChainedCall {
            program_account_id: callee_account_id,
            instruction_data: call_instruction_data.clone(),
            shard_selectors: permuted.clone(),
            pda_seeds: pda_seed.iter().copied().collect(),
        });
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

/// Writes the instruction bytes into the account's shard.
pub fn data_writer() {
    let call = read_lee_call::<Vec<u8>>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: data,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let post_data = data
        .try_into()
        .expect("provided data should fit into data limit");

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![ShardStateDiff::new(pre, post_data)],
    )
    .write();
}

/// Spends from a private PDA via the native token program: `pre_states = [pda, recipient]`.
/// The PDA-to-npk binding is established via `pda_seeds` in the chained transfer.
pub fn pda_spend_proxy() {
    let call = read_lee_call::<(PdaSeed, u128)>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (seed, amount),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([first, second]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let chained_call = custody_transfer(first.account_id, seed, second.account_id, amount);

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![
            ShardStateDiff::unchanged(first),
            ShardStateDiff::unchanged(second),
        ],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
