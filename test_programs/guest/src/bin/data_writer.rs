use lee_core::{
    account::BalanceDiff,
    program::{
        AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

type Instruction = Vec<u8>;

/// Writes the instruction bytes into the account's data.
fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: data,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([pre]) = <[_; 1]>::try_from(pre_states) else {
        return;
    };

    let post_data = data
        .try_into()
        .expect("provided data should fit into data limit");
    let diff_output = AccountStateDiff::new(pre, BalanceDiff::Add(0), post_data);

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![diff_output],
    )
    .write();
}
