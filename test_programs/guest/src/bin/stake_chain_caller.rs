use lee_core::program::{
    AccountPostState, ChainedCall, InstructionData, ProgramId, ProgramInput, ProgramOutput,
    read_lee_inputs,
};

/// A program whose only job is to originate a chained call: it forwards a
/// caller-supplied instruction to a caller-supplied program, passing its own
/// input accounts straight through. Used to reach the `caller_program_id`
/// guards in programs that reject being invoked as a chained call — e.g.
/// `sequencer_stake`'s `Stake` (top-level only) and `ConfirmStake`
/// (self-chained only).
type Instruction = (ProgramId, InstructionData);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (target_program_id, forwarded_instruction_data),
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    // Leave every input account untouched; this program exists only to be the
    // caller of `target_program_id`, never to mutate state itself.
    let post_states = pre_states
        .iter()
        .map(|pre| AccountPostState::new(pre.account.clone()))
        .collect::<Vec<_>>();

    // Forward the same pre-states into the chained call. The callee sees this
    // program as its `caller_program_id`.
    let chained_call = ChainedCall {
        program_id: target_program_id,
        pre_states: pre_states.clone(),
        instruction_data: forwarded_instruction_data,
        pda_seeds: Vec::new(),
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
