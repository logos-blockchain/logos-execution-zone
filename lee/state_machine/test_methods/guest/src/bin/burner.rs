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
            instruction: balance_to_burn,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    // Clamp to preserve the old saturating_sub semantics (burn at most what's there).
    let burned = balance_to_burn.min(pre.account.balance);
    let post_data = pre.account.data.clone();
    let diff = AccountStateDiff::new(pre, BalanceDiff::Sub(burned), post_data);

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![diff],
    )
    .write();
}
