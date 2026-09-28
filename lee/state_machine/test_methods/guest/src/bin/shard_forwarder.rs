use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{ChainedCall, InstructionData, Plan, ProgramCall, read_program_call},
};

type Instruction = Vec<(AccountId, ProgramShardSelector, InstructionData)>;

fn main() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<Instruction>() else {
        panic!("shard_forwarder emits no effect to apply")
    };
    let callees = instruction;

    let Ok([_own]) = <[_; 1]>::try_from(input.accounts.clone()) else {
        panic!("shard_forwarder requires exactly 1 account");
    };

    let mut plan = Plan::new(&input);
    for (callee, shard_selector, callee_instruction) in callees {
        plan.call(ChainedCall {
            program_account_id: callee,
            instruction_data: callee_instruction,
            shard_selectors: vec![shard_selector],
            pda_seeds: vec![],
        });
    }
    plan.write()
}
