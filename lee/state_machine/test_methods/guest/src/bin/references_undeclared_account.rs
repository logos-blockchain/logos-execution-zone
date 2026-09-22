use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{ChainedCall, InstructionData, LeeCall, Plan, ProgramId, read_lee_call},
};

/// Chains to `callee_program_id` naming `undeclared_account_id`, an account never among this
/// program's own handles.
type Instruction = (ProgramId, InstructionData, AccountId);

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("references_undeclared_account emits no effect to resolve")
    };
    let (callee_program_id, callee_instruction, undeclared_account_id) = input.instruction.clone();

    let mut plan = Plan::new(&input, instruction_data);
    plan.call(ChainedCall {
        program_account_id: callee_program_id.into(),
        instruction_data: callee_instruction,
        shard_selectors: vec![ProgramShardSelector::balance(undeclared_account_id)],
        pda_seeds: vec![],
    });
    plan.write()
}
