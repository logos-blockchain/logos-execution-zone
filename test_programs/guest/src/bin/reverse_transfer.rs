use lee_core::{
    account::ProgramShardSelector,
    native_token::{Instruction as NativeInstruction, NATIVE_TOKEN_PROGRAM_ID},
    program::{
        ChainedCall, ProgramCall, ProgramInput, ProgramOutput, ShardStateDiff, read_lee_call,
        respond_unsupported_call,
    },
};

type Instruction = u128;

/// Moves balance out of the SECOND account into the first — the direction a
/// callee handed someone else's account would take to help itself.
fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: amount,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([recipient, source]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let transfer = ChainedCall::new(
        NATIVE_TOKEN_PROGRAM_ID,
        vec![
            ProgramShardSelector::from(&source),
            ProgramShardSelector::from(&recipient),
        ],
        &NativeInstruction::Transfer { amount },
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![
            ShardStateDiff::unchanged(recipient),
            ShardStateDiff::unchanged(source),
        ],
    )
    .with_chained_calls(vec![transfer])
    .write();
}
