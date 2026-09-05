use lee_core::{
    account::Position,
    program::{
        ChainedCall, InstructionData, PdaSeed, ProgramCall, ProgramId, ProgramInput, ProgramOutput,
        ShardStateDiff, read_lee_call, respond_unsupported_call,
    },
};

type Instruction = (ProgramId, InstructionData, bool, Vec<PdaSeed>);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (callee_program_id, callee_instruction, declare_pre_states, pda_seeds),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let positions: Vec<_> = pre_states.iter().map(Position::from).collect();

    let output_state_diffs = if declare_pre_states {
        pre_states
            .iter()
            .map(|account| ShardStateDiff::unchanged(account.clone()))
            .collect()
    } else {
        Vec::new()
    };

    // Make exactly one chained call based on the input instruction, forwarding whatever
    // pda_seeds it was given (typically none, so the target PDAs are never authorized) —
    // this program never writes to the accounts it forwards.
    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        output_state_diffs,
    )
    .with_chained_calls(vec![ChainedCall {
        program_account_id: callee_program_id.into(),
        instruction_data: callee_instruction,
        positions,
        pda_seeds,
    }])
    .write();
}
