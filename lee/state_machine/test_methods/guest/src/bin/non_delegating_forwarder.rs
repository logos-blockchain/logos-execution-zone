use lee_core::program::{
    AccountPostState, ChainedCall, InstructionData, PdaSeed, ProgramId, ProgramInput,
    ProgramOutput, read_lee_inputs,
};

type Instruction = (ProgramId, InstructionData, bool, Vec<PdaSeed>);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (callee_program_id, callee_instruction, declare_pre_states, pda_seeds),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let pre_state_ids: Vec<_> = pre_states.iter().map(|pre| pre.account_id).collect();

    let (output_pre_states, output_post_states) = if declare_pre_states {
        let post_states = pre_states
            .iter()
            .map(|account| AccountPostState::new(account.account.clone()))
            .collect();
        (pre_states, post_states)
    } else {
        (Vec::new(), Vec::new())
    };

    // Make exactly one chained call based on the input instruction, forwarding whatever
    // pda_seeds it was given (typically none, so the target PDAs are never authorized) —
    // this program never claims or otherwise touches the accounts it forwards.
    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        output_pre_states,
        output_post_states,
    )
    .with_chained_calls(vec![ChainedCall {
        program_account_id: callee_program_id.into(),
        instruction_data: callee_instruction,
        pre_state_ids,
        pda_seeds,
    }])
    .write();
}
