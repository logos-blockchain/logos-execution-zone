use lee_core::{
    account::AccountId,
    program::{
        AccountPostState, ChainedCall, InstructionData, ProgramId, ProgramInput, ProgramOutput,
        read_lee_inputs,
    },
};

/// Chains to `callee_program_id` naming `undeclared_account_id`, an account never in this
/// program's own `pre_states`.
type Instruction = (ProgramId, InstructionData, AccountId);

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (callee_program_id, callee_instruction, undeclared_account_id),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let post_states = pre_states
        .iter()
        .map(|account| AccountPostState::new(account.account.clone()))
        .collect();

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .with_chained_calls(vec![ChainedCall {
        program_account_id: callee_program_id.into(),
        instruction_data: callee_instruction,
        pre_state_ids: vec![undeclared_account_id],
        pda_seeds: vec![],
    }])
    .write();
}
