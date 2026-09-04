use lee_core::{
    account::{AccountId, Position},
    program::{
        ChainedCall, InstructionData, ProgramCall, ProgramId, ProgramInput, ProgramOutput,
        ShardStateDiff, read_lee_call, respond_unsupported_call,
    },
};

/// Chains to `callee_program_id` naming `undeclared_account_id`, an account never in this
/// program's own `pre_states`.
type Instruction = (ProgramId, InstructionData, AccountId);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (callee_program_id, callee_instruction, undeclared_account_id),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let state_diffs = pre_states
        .into_iter()
        .map(ShardStateDiff::unchanged)
        .collect();

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .with_chained_calls(vec![ChainedCall {
        program_account_id: callee_program_id.into(),
        instruction_data: callee_instruction,
        positions: vec![Position::balance_only(undeclared_account_id)],
        pda_seeds: vec![],
    }])
    .write();
}
