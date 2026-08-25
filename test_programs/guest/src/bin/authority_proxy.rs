use lee_core::program::{
    ChainedCall, InstructionData, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs,
};

/// Chain-calls an arbitrary target with caller-supplied instruction data, forwarding every
/// account it was given. A callee that gates on a program-held authority re-derives it from
/// this program's id and a seed carried in `target_instruction_data`.
type Instruction = (ProgramId, InstructionData);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (target_program_id, target_instruction_data),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let chained_call = ChainedCall {
        program_id: target_program_id,
        instruction_data: target_instruction_data,
        pre_states: pre_states.clone(),
    };

    let post_states = pre_states.iter().map(|pre| pre.account.clone()).collect();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
