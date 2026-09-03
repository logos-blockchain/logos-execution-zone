use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

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

    if let Ok([account_pre]) = <[_; 1]>::try_from(pre_states.clone()) {
        let post_data = account_pre.account.data.clone();
        let diff_output = AccountStateDiff::new_claimed_if_default(
            account_pre,
            BalanceDiff::Add(0),
            post_data,
            Claim::Authorized,
        );

        ProgramOutput::new(
            self_account_id,
            caller_account_id,
            instruction_data,
            vec![diff_output],
        )
        .write();
        return;
    }

    let Ok([sender_pre, receiver_pre]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let sender_post_data = sender_pre.account.data.clone();
    let receiver_post_data = receiver_pre.account.data.clone();

    let sender_diff = AccountStateDiff::new_claimed_if_default(
        sender_pre,
        BalanceDiff::Sub(balance),
        sender_post_data,
        Claim::Authorized,
    );
    let receiver_diff = AccountStateDiff::new_claimed_if_default(
        receiver_pre,
        BalanceDiff::Add(balance),
        receiver_post_data,
        Claim::Authorized,
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![sender_diff, receiver_diff],
    )
    .write();
}
