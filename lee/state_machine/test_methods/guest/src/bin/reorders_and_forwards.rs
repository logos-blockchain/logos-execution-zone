use lee_core::{
    account::ProgramShardSelector,
    program::{
        ChainedCall, InstructionData, PdaSeed, ProgramCall, ProgramId, ProgramInput, ProgramOutput,
        read_lee_call, respond_unsupported_call,
    },
};

/// Reports empty pre/post (pure passthrough) and forwards its two `pre_states` to one callee in
/// reversed order, delegating `pda_seeds`.
type Instruction = (ProgramId, InstructionData, Vec<PdaSeed>);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (callee_program_id, callee_instruction, pda_seeds),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([first, second]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        Vec::new(),
    )
    .with_chained_calls(vec![ChainedCall {
        program_account_id: callee_program_id.into(),
        instruction_data: callee_instruction,
        shard_selectors: vec![
            ProgramShardSelector::from(&second),
            ProgramShardSelector::from(&first),
        ],
        pda_seeds,
    }])
    .write();
}
