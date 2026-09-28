use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{
        ChainedCall, InstructionData, PdaSeed, Plan, ProgramCall, ProgramId, read_program_call,
    },
};

type Instruction = (ProgramId, InstructionData, Vec<PdaSeed>);

fn main() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<Instruction>() else {
        panic!("reorders_and_forwards emits no effect to apply")
    };
    let (callee_program_id, callee_instruction, pda_seeds) = instruction;

    let Ok([first, second]) = <[_; 2]>::try_from(input.accounts.clone()) else {
        return;
    };

    let mut plan = Plan::new(&input);
    plan.call(ChainedCall {
        program_account_id: AccountId::from_builtin_program(callee_program_id),
        instruction_data: callee_instruction,
        shard_selectors: vec![
            ProgramShardSelector::from(&second),
            ProgramShardSelector::from(&first),
        ],
        pda_seeds,
    });
    plan.write()
}
