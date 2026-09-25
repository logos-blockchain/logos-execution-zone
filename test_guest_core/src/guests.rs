//! Guest bodies shared by both test-guest crates, so the same fixture behaviour cannot drift
//! between them. Each crate still ships its own binary, and so its own image id.

use lee_core::{
    account::ProgramShardSelector,
    native_token::custody_transfer,
    program::{
        ChainedCall, GuestOutput, PdaSeed, Plan, PlanOutput, ProgramCall, ShardEffect, apply_write,
        read_program_call,
    },
};

use crate::ChainCall;

/// Calls another program `calls` times, permuting the input account order on each call.
pub fn chain_caller() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<ChainCall>() else {
        panic!("chain_caller emits no effect to apply")
    };
    let ChainCall {
        callee_account_id,
        instruction_data: call_instruction_data,
        calls,
        pda_seed,
    } = instruction;

    let Ok([recipient, sender]) = <[_; 2]>::try_from(input.accounts.clone()) else {
        return;
    };

    let permuted = vec![
        ProgramShardSelector::from(&sender),
        ProgramShardSelector::from(&recipient),
    ];

    let mut plan = Plan::new(&input);
    for _ in 0..calls {
        plan.call(ChainedCall {
            program_account_id: callee_account_id,
            instruction_data: call_instruction_data.clone(),
            shard_selectors: permuted.clone(),
            pda_seeds: pda_seed.iter().copied().collect(),
        });
    }
    plan.write();
}

/// Writes the instruction bytes into the account's shard.
pub fn data_writer() {
    match read_program_call::<Vec<u8>>() {
        ProgramCall::Plan(input, instruction) => {
            let Ok([account]) = <[_; 1]>::try_from(input.accounts.clone()) else {
                panic!("data_changer requires exactly 1 account");
            };
            let effect = ShardEffect::new(&account, &instruction);
            GuestOutput::Plan(PlanOutput::new(input).with_effects(vec![effect])).write();
        }
        ProgramCall::Apply(input) => {
            let written: Vec<u8> =
                borsh::from_slice(&input.effect_data).expect("data_writer wrote its own effect");
            let data = written
                .try_into()
                .expect("written data fits the data limit");
            apply_write(input, data);
        }
    }
}

/// Spends from a private PDA via the native token program: `accounts = [pda, recipient]`.
/// The PDA-to-npk binding is established via `pda_seeds` in the chained transfer.
pub fn pda_spend_proxy() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<(PdaSeed, u128)>() else {
        panic!("pda_spend_proxy emits no effect to apply")
    };
    let (seed, amount) = instruction;

    let Ok([first, second]) = <[_; 2]>::try_from(input.accounts.clone()) else {
        return;
    };

    let mut plan = Plan::new(&input);
    plan.call(custody_transfer(
        first.account_id,
        seed,
        second.account_id,
        amount,
    ));
    plan.write();
}
