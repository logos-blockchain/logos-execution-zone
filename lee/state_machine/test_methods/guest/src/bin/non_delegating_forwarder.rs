use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{
        ChainedCall, GuestOutput, InstructionData, PdaSeed, PlanInput, PlanOutput, ProgramCall,
        ProgramId, read_program_call,
    },
};

type Instruction = (ProgramId, InstructionData, bool, Vec<PdaSeed>);

fn main() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<Instruction>() else {
        panic!("non_delegating_forwarder emits no effect to apply")
    };
    let (callee_program_id, callee_instruction, declare_accounts, pda_seeds) = instruction;

    let shard_selectors: Vec<_> = input
        .accounts
        .iter()
        .map(ProgramShardSelector::from)
        .collect();
    let accounts = if declare_accounts {
        input.accounts
    } else {
        Vec::new()
    };

    GuestOutput::Plan(
        PlanOutput::new(PlanInput { accounts, ..input }).with_chained_calls(vec![ChainedCall {
            program_account_id: AccountId::from_builtin_program(callee_program_id),
            instruction_data: callee_instruction,
            shard_selectors,
            pda_seeds,
        }]),
    )
    .write();
}
