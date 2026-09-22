use lee_core::{
    account::ProgramShardSelector,
    program::{ChainedCall, InstructionData, LeeCall, PdaSeed, Plan, ProgramId, read_lee_call},
};

type Instruction = (InstructionData, ProgramId, u32, Option<PdaSeed>);

/// A program that calls another program `num_chain_calls` times.
/// It permutes the order of the input accounts on the subsequent call.
fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("chain_caller emits no effect to resolve")
    };
    let (call_instruction_data, callee_program_id, num_chain_calls, pda_seed) =
        input.instruction.clone();

    let Ok([recipient, sender]) = <[_; 2]>::try_from(input.accounts.clone()) else {
        return;
    };

    // Account order permuted here (sender before recipient).
    let permuted = vec![
        ProgramShardSelector::from(&sender),
        ProgramShardSelector::from(&recipient),
    ];

    let mut plan = Plan::new(&input, instruction_data);
    for _i in 0..num_chain_calls {
        plan.call(ChainedCall {
            program_account_id: callee_program_id.into(),
            instruction_data: call_instruction_data.clone(),
            shard_selectors: permuted.clone(),
            pda_seeds: pda_seed.iter().copied().collect(),
        });
    }
    plan.write()
}
