use borsh::to_vec;
use lee_core::program::{
    AccountPostState, ChainedCall, Claim, InstructionData, PdaSeed, ProgramId, ProgramInput,
    ProgramOutput, read_lee_inputs,
};

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
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let Some((pda, rest)) = pre_states.split_first() else {
        return;
    };

    // Delegate the PDA to the callee via `pda_seeds` — the protocol resolves its
    // authorization there from the seed match, not from anything supplied here.
    let mut chained_calls = vec![ChainedCall {
        program_id: callee_program_id,
        instruction_data: callee_instruction,
        accounts: std::iter::once(pda.account_id)
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
            accounts: if include_pda {
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
        instruction_data,
        vec![pda.clone()],
        // Claim first PDA supplied
        vec![AccountPostState::new_claimed(
            pda.account.clone(),
            Claim::Pda(claim_seed),
        )],
    )
    .with_chained_calls(chained_calls)
    .write();
}
