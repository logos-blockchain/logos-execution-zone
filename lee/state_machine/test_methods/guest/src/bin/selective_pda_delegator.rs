use lee_core::{
    account::{AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, ChainedCall, Claim, InstructionData, PdaSeed, ProgramCall, ProgramId,
        ProgramInput, ProgramOutput, read_lee_call,
    },
};
use risc0_zkvm::serde::to_vec;

type Instruction = (
    PdaSeed,
    PdaSeed,
    ProgramId,
    InstructionData,
    Option<(ProgramId, bool)>,
);

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction:
                (claim_seed, delegated_seed, callee_program_id, callee_instruction, sibling),
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "selective_pda_delegator program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    let Some((pda, rest)) = pre_states.split_first() else {
        return;
    };

    // Delegate the PDA to the callee via `pda_seeds` — the protocol resolves its
    // authorization there from the seed match, not from anything supplied here.
    let mut chained_calls = vec![ChainedCall {
        program_id: callee_program_id,
        instruction_data: callee_instruction,
        pre_state_refs: std::iter::once(pda.account_id)
            .chain(rest.iter().map(|r| r.account_id))
            .collect(),
        pda_seeds: vec![delegated_seed],
    }];

    // If sibling is present, send out a call with no seeds so the PDA (when included)
    // stays unauthorized in that parallel branch.
    if let Some((sibling_program_id, include_pda)) = sibling {
        chained_calls.push(ChainedCall {
            program_id: sibling_program_id,
            instruction_data: to_vec(&()).unwrap(),
            pre_state_refs: if include_pda {
                std::iter::once(pda.account_id)
                    .chain(rest.iter().map(|r| r.account_id))
                    .collect()
            } else {
                rest.iter().map(|r| r.account_id).collect()
            },
            pda_seeds: vec![],
        });
    }

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pda.clone()],
        // Claim first PDA supplied
        vec![AccountDiffOutput::new_claimed(
            AccountDiff {
                id: pda.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: None,
            },
            Claim::Pda(claim_seed),
        )],
    )
    .with_chained_calls(chained_calls)
    .write();
}
