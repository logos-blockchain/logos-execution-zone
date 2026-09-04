use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

/// Same transfer as `simple_balance_transfer`, but reports its two diffs in the opposite order
/// from `pre_states` — proves order is irrelevant now that each diff embeds its own pre-state,
/// unlike the old two-array `pre_states`/`post_diffs` shape where a reordered report was rejected.
type Instruction = u128;

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

    let Ok([sender_pre, receiver_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let sender_diff = AccountStateDiff::new(
        sender_pre.clone(),
        BalanceDiff::Sub(balance),
        sender_pre.account.data,
    );
    let receiver_diff = AccountStateDiff::new(
        receiver_pre.clone(),
        BalanceDiff::Add(balance),
        receiver_pre.account.data,
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        // Swapped: receiver's diff first, sender's second.
        vec![receiver_diff, sender_diff],
    )
    .write();
}
