use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
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

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![
            AccountStateDiff::new(
                sender_pre.clone(),
                BalanceDiff::Sub(balance),
                sender_pre.account.data,
            ),
            AccountStateDiff::new(
                receiver_pre.clone(),
                BalanceDiff::Add(balance),
                receiver_pre.account.data,
            ),
        ],
    )
    .write();
}
