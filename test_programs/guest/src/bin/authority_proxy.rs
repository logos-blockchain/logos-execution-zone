use lee_core::{
    account::{AccountDiff, AccountId, BalanceDiff},
    program::{
        AccountDiffOutput, ChainedCall, PdaSeed, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call,
    },
};

/// Chain-calls an arbitrary target with caller-supplied instruction words,
/// forwarding every account it was given. With a seed, the PDA derived from
/// `(self, seed)` is delegated through `pda_seeds` and flagged authorized in the
/// call, which is how a program-held authority acts on a callee.
type Instruction = (ProgramId, Vec<u32>, Option<PdaSeed>);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (target_program_id, target_instruction_words, pda_seed),
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "authority_proxy program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    let mut call_pre_states = pre_states.clone();
    if let Some(seed) = pda_seed {
        let delegated = AccountId::for_public_pda(&self_program_id, &seed);
        for pre in &mut call_pre_states {
            if pre.account_id == delegated {
                pre.is_authorized = true;
            }
        }
    }

    let chained_call = ChainedCall {
        program_id: target_program_id,
        instruction_data: target_instruction_words,
        pre_states: call_pre_states,
        pda_seeds: pda_seed.into_iter().collect(),
    };

    let post_states = pre_states
        .iter()
        .map(|pre| {
            AccountDiffOutput::new(AccountDiff {
                id: pre.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: None,
            })
        })
        .collect();

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
