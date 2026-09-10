use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

type Instruction = u128;

/// `simple_balance_transfer`'s twin, opted into `CallKind::Incremental` instead of `Execute`:
/// its diffs never read from `pre_state` (the moved amount comes from the instruction alone,
/// and data is always left unchanged), so replaying them against any current `pre_state` is
/// exactly as safe as replaying them against the one they were computed against.
fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Incremental(ProgramInput {
        self_account_id,
        caller_account_id,
        pre_states,
        instruction: instruction_data,
    }) = call
    else {
        respond_unsupported_call(call);
    };
    let balance: Instruction =
        borsh::from_slice(&instruction_data).expect("instruction must decode from borsh");

    if let Ok([account_pre]) = <[_; 1]>::try_from(pre_states.clone()) {
        let diff_output = AccountStateDiff::unchanged(account_pre);

        ProgramOutput::new(
            self_account_id,
            caller_account_id,
            instruction_data,
            vec![diff_output],
        )
        .with_call_kind(lee_core::program::CallKind::Incremental)
        .write();
        return;
    }

    let Ok([sender_pre, receiver_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let sender_post_data = sender_pre.account.data.clone();
    let receiver_post_data = receiver_pre.account.data.clone();

    let sender_diff =
        AccountStateDiff::new(sender_pre, BalanceDiff::Sub(balance), sender_post_data);
    let receiver_diff =
        AccountStateDiff::new(receiver_pre, BalanceDiff::Add(balance), receiver_post_data);

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![sender_diff, receiver_diff],
    )
    .with_call_kind(lee_core::program::CallKind::Incremental)
    .write();
}
