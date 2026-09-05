use borsh::to_vec;
use lee_core::{
    account::Position,
    program::{
        ChainedCall, InstructionData, PdaSeed, ProgramCall, ProgramId, ProgramInput, ProgramOutput,
        ShardStateDiff, read_lee_call, respond_unsupported_call,
    },
};

type Instruction = (
    PdaSeed,
    ProgramId,
    InstructionData,
    Option<(ProgramId, bool)>,
);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (delegated_seed, callee_program_id, callee_instruction, sibling),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Some((pda, rest)) = pre_states.split_first() else {
        return;
    };

    // Delegate the PDA to the callee via `pda_seeds` — the protocol resolves its
    // authorization there from the seed match, not from anything supplied here.
    let mut chained_calls = vec![ChainedCall {
        program_account_id: callee_program_id.into(),
        instruction_data: callee_instruction,
        positions: std::iter::once(Position::from(pda))
            .chain(rest.iter().map(Position::from))
            .collect(),
        pda_seeds: vec![delegated_seed],
    }];

    // If sibling is present, send out a call with no seeds so the PDA (when included)
    // stays unauthorized in that parallel branch.
    if let Some((sibling_program_id, include_pda)) = sibling {
        chained_calls.push(ChainedCall {
            program_account_id: sibling_program_id.into(),
            instruction_data: to_vec(&()).unwrap(),
            positions: if include_pda {
                std::iter::once(Position::from(pda))
                    .chain(rest.iter().map(Position::from))
                    .collect()
            } else {
                rest.iter().map(Position::from).collect()
            },
            pda_seeds: vec![],
        });
    }

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![ShardStateDiff::unchanged(pda.clone())],
    )
    .with_chained_calls(chained_calls)
    .write();
}
