use lee_core::{
    account::ProgramShardSelector,
    program::{ChainedCall, InstructionData, LeeCall, PdaSeed, Plan, ProgramId, read_lee_call},
};

type Instruction = (ProgramId, InstructionData, Vec<PdaSeed>);

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("reorders_and_forwards emits no effect to resolve")
    };
    let (callee_program_id, callee_instruction, pda_seeds) = input.instruction.clone();

    let Ok([first, second]) = <[_; 2]>::try_from(input.accounts.clone()) else {
        return;
    };

    let mut plan = Plan::new(&input, instruction_data);
    plan.call(ChainedCall {
        program_account_id: callee_program_id.into(),
        instruction_data: callee_instruction,
        shard_selectors: vec![
            ProgramShardSelector::from(&second),
            ProgramShardSelector::from(&first),
        ],
        pda_seeds,
    });
    plan.write()
}
