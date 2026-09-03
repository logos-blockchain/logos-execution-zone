use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

type Instruction = (Option<Vec<u8>>, bool);

/// A program that optionally modifies the account data and optionally claims it.
fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (data_opt, should_claim),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    // Update data if provided, otherwise leave it unchanged.
    let post_data = match data_opt {
        Some(data) => data
            .try_into()
            .expect("provided data should fit into data limit"),
        None => pre.account.data.clone(),
    };

    // Claim or not based on the boolean flag
    let state_diff = if should_claim {
        AccountStateDiff::new_claimed(pre, BalanceDiff::Add(0), post_data, Claim::Authorized)
    } else {
        AccountStateDiff::new(pre, BalanceDiff::Add(0), post_data)
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![state_diff],
    )
    .write();
}
