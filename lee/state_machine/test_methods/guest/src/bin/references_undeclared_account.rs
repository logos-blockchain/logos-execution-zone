use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{ChainedCall, InstructionData, Plan, ProgramCall, ProgramId, read_program_call},
};

/// Chains to `callee_program_id` naming `undeclared_account_id`, an account never among this
/// program's own handles.
type Instruction = (ProgramId, InstructionData, AccountId);

fn main() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<Instruction>() else {
        panic!("references_undeclared_account emits no effect to apply")
    };
    let (callee_program_id, callee_instruction, undeclared_account_id) = instruction;

    let mut plan = Plan::new(&input);
    plan.call(ChainedCall {
        program_account_id: AccountId::from_builtin_program(callee_program_id),
        instruction_data: callee_instruction,
        shard_selectors: vec![ProgramShardSelector::native_balance(undeclared_account_id)],
        pda_seeds: vec![],
    });
    plan.write()
}
