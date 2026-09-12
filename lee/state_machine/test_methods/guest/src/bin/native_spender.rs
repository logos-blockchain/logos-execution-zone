use lee_core::{
    account::ProgramShardSelector,
    native_token::{Instruction as NativeInstruction, NATIVE_TOKEN_PROGRAM_ID},
    program::{
        AccountStateDiff, ChainedCall, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

type Instruction = (Vec<u8>, u128);

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (own_data, amount),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([own_pre, sender_pre, recipient_pre]) = <[_; 3]>::try_from(pre_states) else {
        panic!("expected exactly 3 pre_states: [own shard, sender balance, recipient balance]");
    };

    let transfer = ChainedCall::new(
        NATIVE_TOKEN_PROGRAM_ID,
        vec![
            ProgramShardSelector::from(&sender_pre),
            ProgramShardSelector::from(&recipient_pre),
        ],
        &NativeInstruction::Transfer { amount },
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![
            AccountStateDiff::new(
                own_pre,
                own_data
                    .try_into()
                    .expect("provided data should fit into data limit"),
            ),
            AccountStateDiff::unchanged(sender_pre),
            AccountStateDiff::unchanged(recipient_pre),
        ],
    )
    .with_chained_calls(vec![transfer])
    .write();
}
