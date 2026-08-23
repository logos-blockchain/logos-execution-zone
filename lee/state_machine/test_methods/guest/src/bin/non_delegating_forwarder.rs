use lee_core::{
    account::AccountId,
    program::{
        AccountPostState, ChainedCall, InstructionData, ProgramInput, ProgramOutput,
        read_lee_inputs,
    },
};

type Instruction = (AccountId, InstructionData, bool);

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (callee_account_id, callee_instruction, declare_pre_states),
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let (output_pre_states, output_post_states) = if declare_pre_states {
        let post_states = pre_states
            .iter()
            .map(|account| AccountPostState::new(account.account.clone()))
            .collect();
        (pre_states.clone(), post_states)
    } else {
        (Vec::new(), Vec::new())
    };

    // Make exactly one chained call based on the input instruction with no
    // pda seeds, ensuring the target PDAs are never authorized.
    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_words,
        output_pre_states,
        output_post_states,
    )
    .with_chained_calls(vec![ChainedCall {
        program_account_id: callee_account_id,
        instruction_data: callee_instruction,
        pre_states,
        pda_seeds: vec![],
        raw_payload: None,
    }])
    .write();
}
