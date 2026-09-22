use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{ChainedCall, InstructionData, LeeCall, Plan, read_lee_call},
};

type Instruction = Vec<(AccountId, ProgramShardSelector, InstructionData)>;

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("shard_forwarder emits no effect to resolve")
    };
    let callees = input.instruction.clone();

    let Ok([_own]) = <[_; 1]>::try_from(input.accounts.clone()) else {
        return;
    };

    let mut plan = Plan::new(&input, instruction_data);
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
