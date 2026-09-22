use borsh::to_vec;
use lee_core::{
    account::ProgramShardSelector,
    program::{ChainedCall, LeeCall, PdaSeed, Plan, ProgramId, read_lee_call},
};

/// Chains to `callee_program_id`, delegating authorization over its sole handle with
/// `delegated_seed` in `pda_seeds`.
type Instruction = (PdaSeed, ProgramId);

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("private_pda_delegator emits no effect to resolve")
    };
    let (delegated_seed, callee_program_id) = input.instruction;

    let Ok([account]) = <[_; 1]>::try_from(input.accounts.clone()) else {
        return;
    };

    let mut plan = Plan::new(&input, instruction_data);
    plan.call(ChainedCall {
        program_account_id: callee_program_id.into(),
        instruction_data: to_vec(&()).unwrap(),
        shard_selectors: vec![ProgramShardSelector::from(&account)],
        pda_seeds: vec![delegated_seed],
    });
    plan.write()
}
