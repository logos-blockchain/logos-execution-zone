use lee_core::program::{
    AccountStateDiff, ChainedCall, InstructionData, PdaSeed, ProgramCall, ProgramId, ProgramInput,
    ProgramOutput, read_lee_call, respond_unsupported_call,
};

/// Chain-calls an arbitrary target with caller-supplied instruction data,
/// forwarding every account it was given. With a seed, the PDA derived from
/// `(self, seed)` is delegated through `pda_seeds`, which is how a program-held
/// authority acts on a callee.
type Instruction = (ProgramId, InstructionData, Option<PdaSeed>);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (target_program_id, target_instruction_data, pda_seed),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let chained_call = ChainedCall {
        program_account_id: target_program_id.into(),
        instruction_data: target_instruction_data,
        pre_state_ids: pre_states.iter().map(|pre| pre.account_id).collect(),
        pda_seeds: pda_seed.into_iter().collect(),
    };

    let state_diffs = pre_states
        .iter()
        .map(|pre| AccountStateDiff::unchanged(pre.clone()))
        .collect();

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
