use lee_core::{
    account::ProgramShardSelector,
    program::{
        AccountStateDiff, ChainedCall, InstructionData, PdaSeed, ProgramCall, ProgramId,
        ProgramInput, ProgramOutput, read_lee_call, respond_unsupported_call,
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

    let shard_selectors: Vec<_> = pre_states.iter().map(ProgramShardSelector::from).collect();

    let output_state_diffs = if declare_pre_states {
        pre_states
            .iter()
            .map(|account| AccountStateDiff::unchanged(account.clone()))
            .collect()
    } else {
        Vec::new()
    };

    // Forward the inputs and supplied PDA seeds in one chained call.
    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        output_state_diffs,
    )
    .with_chained_calls(vec![ChainedCall {
        program_account_id: callee_program_id.into(),
        instruction_data: callee_instruction,
        shard_selectors,
        pda_seeds,
    }])
    .write();
}
