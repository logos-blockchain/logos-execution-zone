use lee_core::{
    account::ProgramShardSelector,
    program::{
        ChainedCall, GuestOutput, InstructionData, LeeCall, PdaSeed, ProgramId, ProgramOutput,
        read_lee_call,
    },
};

/// Forwards its handles and the supplied PDA seeds in one chained call. `declare_accounts`
/// selects whether it echoes the handles it was given at all, so the `false` case exercises a
/// planner that under-reports its own input.
type Instruction = (ProgramId, InstructionData, bool, Vec<PdaSeed>);

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("non_delegating_forwarder emits no effect to resolve")
    };
    let (callee_program_id, callee_instruction, declare_accounts, pda_seeds) = input.instruction;

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

    GuestOutput::Execute(
        ProgramOutput::new(
            input.self_account_id,
            input.caller_account_id,
            instruction_data,
            accounts,
        )
        .with_chained_calls(vec![ChainedCall {
            program_account_id: callee_program_id.into(),
            instruction_data: callee_instruction,
            shard_selectors,
            pda_seeds,
        }]),
    )
    .write();
}
