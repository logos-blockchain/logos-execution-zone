use borsh::to_vec;
use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{ChainedCall, PdaSeed, Plan, ProgramCall, ProgramId, read_program_call},
};

/// Chains to `callee_program_id`, delegating authorization over its sole handle with
/// `delegated_seed` in `pda_seeds`.
type Instruction = (PdaSeed, ProgramId);

fn main() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<Instruction>() else {
        panic!("private_pda_delegator emits no effect to apply")
    };
    let (delegated_seed, callee_program_id) = instruction;

    let Ok([account]) = <[_; 1]>::try_from(input.accounts.clone()) else {
        return;
    };

    let mut plan = Plan::new(&input);
    plan.call(ChainedCall {
        program_account_id: AccountId::from_builtin_program(callee_program_id),
        instruction_data: to_vec(&()).unwrap(),
        shard_selectors: vec![ProgramShardSelector::from(&account)],
        pda_seeds: vec![delegated_seed],
    });
    plan.write()
}
