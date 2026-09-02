use lee_core::program::{
    ChainedCall, InstructionData, PdaSeed, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
};

/// Reports empty pre/post (pure passthrough) and forwards its two `pre_states` to one callee in
/// reversed order, delegating `pda_seeds`.
type Instruction = (ProgramId, InstructionData, Vec<PdaSeed>);

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (callee_program_id, callee_instruction, pda_seeds),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([first, second]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        Vec::new(),
        Vec::new(),
    )
    .with_chained_calls(vec![ChainedCall {
        program_account_id: callee_program_id.into(),
        instruction_data: callee_instruction,
        pre_state_ids: vec![second.account_id, first.account_id],
        pda_seeds,
    }])
    .write();
}
