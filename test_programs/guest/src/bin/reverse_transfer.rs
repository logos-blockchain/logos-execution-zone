use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
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

    let recipient_diff = AccountStateDiff::new(
        recipient.clone(),
        BalanceDiff::Add(amount),
        recipient.account.data,
    );

    let source_diff = AccountStateDiff::new(
        source.clone(),
        BalanceDiff::Sub(amount),
        source.account.data,
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![recipient_diff, source_diff],
    )
    .write();
}
