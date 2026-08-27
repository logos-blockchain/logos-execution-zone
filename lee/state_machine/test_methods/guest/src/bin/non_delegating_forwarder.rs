use lee_core::program::{
    AccountDiffOutput, CallContext, ChainedCall, InstructionData, ProgramCall, ProgramId,
    ProgramInput, ProgramOutput, read_lee_call,
};

type Instruction = (ProgramId, InstructionData, bool);

fn main() {
    let ProgramCall::Execute {
        input,
        instruction: (callee_program_id, callee_instruction, declare_pre_states),
    } = read_lee_call::<Instruction>();
    let ProgramInput {
        call:
            CallContext {
                self_program_id,
                caller_program_id,
                instruction_data,
            },
        pre_states,
    } = input;

    let accounts: Vec<_> = pre_states.iter().map(|pre| pre.account_id).collect();

    let (output_pre_states, output_post_states) = if declare_pre_states {
        let post_states = pre_states
            .iter()
            .map(|account| AccountDiffOutput::unchanged(account.account_id))
            .collect();
        (pre_states, post_states)
    } else {
        (Vec::new(), Vec::new())
    };

    // Make exactly one chained call based on the input instruction with no
    // pda seeds, ensuring the target PDAs are never authorized.
    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        output_pre_states,
        output_post_states,
    )
    .with_chained_calls(vec![ChainedCall {
        program_id: callee_program_id,
        instruction_data: callee_instruction,
        accounts,
        pda_seeds: vec![],
    }])
    .write();
}
