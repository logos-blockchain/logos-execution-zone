use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{
        AccountStateDiff, ChainedCall, InstructionData, PdaSeed, ProgramCall, ProgramId,
        ProgramInput, ProgramOutput, read_lee_call, respond_unsupported_call,
    },
};

/// Echoes its two `pre_states` unchanged and forwards them to one callee in reversed order,
/// delegating `pda_seeds`.
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

    let chained_call = ChainedCall {
        program_account_id: AccountId::from_builtin_program(callee_program_id),
        instruction_data: callee_instruction,
        shard_selectors: vec![
            ProgramShardSelector::from(&second),
            ProgramShardSelector::from(&first),
        ],
        pda_seeds,
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![
            AccountStateDiff::unchanged(first),
            AccountStateDiff::unchanged(second),
        ],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
