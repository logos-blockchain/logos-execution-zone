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
    Option<(ProgramId, Option<bool>)>,
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

    let pda_for_callee = |is_authorized| {
        let mut for_callee = pda.clone();
        for_callee.is_authorized = is_authorized;
        for_callee.account.program_owner = self_program_id.into();
        for_callee
    };

    // Send a call to the specified program with the same pre-states
    // but authorized first PDA supplied.
    // Push all the delegated seeds.
    let mut chained_calls = vec![ChainedCall {
        program_id: callee_program_id,
        instruction_data: callee_instruction,
        pre_states: std::iter::once(pda_for_callee(true))
            .chain(rest.iter().cloned())
            .collect(),
        pda_seeds: vec![delegated_seed],
    }];

    // If sibling is present in instruction, send out a call
    // with no seeds so that PDAs stay unauthorized in parallel
    // branches.
    if let Some((sibling_program_id, sibling_pda)) = sibling {
        chained_calls.push(ChainedCall {
            program_id: sibling_program_id,
            instruction_data: to_vec(&()).unwrap(),
            pre_states: sibling_pda.map_or_else(
                || rest.to_vec(),
                |is_authorized| {
                    std::iter::once(pda_for_callee(is_authorized))
                        .chain(rest.iter().cloned())
                        .collect()
                },
            ),
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
