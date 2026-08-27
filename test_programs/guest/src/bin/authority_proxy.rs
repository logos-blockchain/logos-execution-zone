use lee_core::{
    account::AccountDiff,
    program::{
        AccountDiffOutput, ChainedCall, InstructionData, PdaSeed, ProgramCall, ProgramId,
        ProgramInput, ProgramOutput, read_lee_call,
    },
};

/// Chain-calls an arbitrary target with caller-supplied instruction data,
/// forwarding every account it was given. With a seed, the PDA derived from
/// `(self, seed)` is delegated through `pda_seeds`, which is how a program-held
/// authority acts on a callee.
type Instruction = (ProgramId, InstructionData, Option<PdaSeed>);

fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (target_program_id, target_instruction_data, pda_seed),
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let chained_call = ChainedCall {
        program_id: target_program_id,
        instruction_data: target_instruction_data,
        accounts: pre_states.iter().map(|pre| pre.account_id).collect(),
        pda_seeds: pda_seed.into_iter().collect(),
    };

    let post_states = pre_states
        .iter()
        .map(|pre| AccountDiffOutput::new(AccountDiff::unchanged(pre.account_id)))
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
