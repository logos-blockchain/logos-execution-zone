use lee_core::program::{
    AccountPostState, ChainedCall, InstructionData, PdaSeed, ProgramId, ProgramInput,
    ProgramOutput, read_lee_inputs,
};

/// Chain-calls an arbitrary target with caller-supplied instruction data,
/// forwarding every account it was given. With a seed, the PDA derived from
/// `(self, seed)` is delegated through `pda_seeds`, which is how a program-held
/// authority acts on a callee — the protocol resolves that PDA's authorization
/// from the seed match, not from anything this program declares.
type Instruction = (ProgramId, InstructionData, Option<PdaSeed>);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (target_program_id, target_instruction_data, pda_seed),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let chained_call = ChainedCall {
        program_id: target_program_id,
        instruction_data: target_instruction_data,
        pre_state_refs: pre_states.iter().map(|pre| pre.account_id).collect(),
        pda_seeds: pda_seed.into_iter().collect(),
    };

    let post_states = pre_states
        .iter()
        .map(|pre| AccountPostState::new(pre.account.clone()))
        .collect();

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
