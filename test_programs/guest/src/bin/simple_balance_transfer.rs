use lee_core::{
    account::ProgramShardSelector,
    native_token::{Instruction as NativeInstruction, NATIVE_TOKEN_PROGRAM_ID},
    program::{
        AccountStateDiff, ChainedCall, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

type Instruction = u128;

/// Requests a native transfer of `balance` from the first account to the second.
fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: balance,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    if let Ok([account_pre]) = <[_; 1]>::try_from(pre_states.clone()) {
        let account_post = AccountStateDiff::unchanged(account_pre);

        ProgramOutput::new(
            self_account_id,
            caller_account_id,
            instruction_data,
            vec![account_post],
        )
        .write();
        return;
    }

    let Ok([sender_pre, receiver_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let transfer = ChainedCall::new(
        NATIVE_TOKEN_PROGRAM_ID,
        vec![
            ProgramShardSelector::from(&sender_pre),
            ProgramShardSelector::from(&receiver_pre),
        ],
        &NativeInstruction::Transfer { amount: balance },
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![
            AccountStateDiff::unchanged(sender_pre),
            AccountStateDiff::unchanged(receiver_pre),
        ],
    )
    .with_chained_calls(vec![transfer])
    .write();
}
