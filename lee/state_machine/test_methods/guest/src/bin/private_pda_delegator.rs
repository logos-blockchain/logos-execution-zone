use borsh::to_vec;
use lee_core::{
    account::ProgramShardSelector,
    program::{
        AccountStateDiff, ChainedCall, PdaSeed, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call, respond_unsupported_call,
    },
};

/// Echoes the sole `pre_state` and chains to `callee_program_id`, delegating authorization with
/// `delegated_seed` in `pda_seeds`.
type Instruction = (PdaSeed, ProgramId);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (delegated_seed, callee_program_id),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let chained_call = ChainedCall {
        program_account_id: callee_program_id.into(),
        instruction_data: to_vec(&()).unwrap(),
        shard_selectors: vec![ProgramShardSelector::from(&pre)],
        pda_seeds: vec![delegated_seed],
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![AccountStateDiff::unchanged(pre)],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
