use borsh::to_vec;
use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{
        ChainedCall, InstructionData, PdaSeed, Plan, ProgramCall, ProgramId, read_program_call,
    },
};

type Instruction = (
    PdaSeed,
    ProgramId,
    InstructionData,
    Option<(ProgramId, bool)>,
);

fn main() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<Instruction>() else {
        panic!("selective_pda_delegator emits no effect to apply")
    };
    let (delegated_seed, callee_program_id, callee_instruction, sibling) = instruction;

    let Some((pda, rest)) = input.accounts.split_first() else {
        panic!("selective_pda_delegator requires at least 1 account");
    };

    let mut plan = Plan::new(&input);
    // Delegate the PDA to the callee via `pda_seeds` — the protocol resolves its
    // authorization there from the seed match, not from anything supplied here.
    plan.call(ChainedCall {
        program_account_id: AccountId::from_builtin_program(callee_program_id),
        instruction_data: callee_instruction,
        shard_selectors: std::iter::once(ProgramShardSelector::from(pda))
            .chain(rest.iter().map(ProgramShardSelector::from))
            .collect(),
        pda_seeds: vec![delegated_seed],
    });

    // If sibling is present, send out a call with no seeds so the PDA (when included)
    // stays unauthorized in that parallel branch.
    if let Some((sibling_program_id, include_pda)) = sibling {
        plan.call(ChainedCall {
            program_account_id: AccountId::from_builtin_program(sibling_program_id),
            instruction_data: to_vec(&()).unwrap(),
            shard_selectors: if include_pda {
                std::iter::once(ProgramShardSelector::from(pda))
                    .chain(rest.iter().map(ProgramShardSelector::from))
                    .collect()
            } else {
                rest.iter().map(ProgramShardSelector::from).collect()
            },
            pda_seeds: vec![],
        });
    }
    plan.write()
}
