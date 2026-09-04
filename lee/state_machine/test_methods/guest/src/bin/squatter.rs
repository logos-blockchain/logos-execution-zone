use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

/// The data to write into the first account, and the balance to move out of it.
type Instruction = (Vec<u8>, u128);

/// Writes data to an account it does not own - acquiring it - and moves balance
/// out of it in the same breath.
fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (data, amount),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([target, recipient]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let target_diff = AccountStateDiff::new(
        target,
        BalanceDiff::Sub(amount),
        data.try_into()
            .expect("provided data should fit into data limit"),
    );

    let recipient_diff = AccountStateDiff::new(
        recipient.clone(),
        BalanceDiff::Add(amount),
        recipient.account.data,
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![target_diff, recipient_diff],
    )
    .write();
}
