use lee_core::{
    account::AccountId,
    program::{
        AccountPostState, ChainedCall, InstructionData, PdaSeed, ProgramId, ProgramInput,
        ProgramOutput, read_lee_inputs,
    },
};

/// Chain-calls an arbitrary target with caller-supplied instruction data,
/// forwarding every account it was given. With a seed, the PDA derived from
/// `(self, seed)` is delegated through `pda_seeds` and flagged authorized in the
/// call, which is how a program-held authority acts on a callee.
type Instruction = (ProgramId, InstructionData, Option<PdaSeed>);

fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (target_program_id, target_instruction_data, pda_seed),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let mut call_pre_states = pre_states.clone();
    if let Some(seed) = pda_seed {
        let delegated = AccountId::for_public_pda(&self_account_id, &seed);
        for pre in &mut call_pre_states {
            if pre.account_id == delegated {
                pre.is_authorized = true;
            }
        }
    }

    let chained_call = ChainedCall {
        program_account_id: program_loader_core::immutable_deploy_account_id(target_program_id),
        instruction_data: target_instruction_data,
        pre_states: call_pre_states,
        pda_seeds: pda_seed.into_iter().collect(),
    };

    let post_states = pre_states
        .iter()
        .map(|pre| AccountPostState::new(pre.account.clone()))
        .collect();

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
