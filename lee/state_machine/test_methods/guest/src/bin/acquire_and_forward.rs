use lee_core::program::{
    ChainedCall, InstructionData, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
};

/// Data to write into the account (`None` echoes it instead), the callee to forward it
/// to, and the callee's instruction.
type Instruction = (Option<Vec<u8>>, ProgramId, InstructionData);

/// Acquires the account by writing data to it or echoes, then forwards it to the callee.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (data, callee, callee_instruction),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Ok([target]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let mut target_post = target.account.clone();
    if let Some(data) = data {
        target_post.data = data
            .try_into()
            .expect("provided data should fit into data limit");
    }

    let chained_call = ChainedCall {
        program_id: callee,
        instruction_data: callee_instruction,
        pre_state_ids: vec![target.account_id],
        pda_seeds: vec![],
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![target],
        vec![target_post],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
