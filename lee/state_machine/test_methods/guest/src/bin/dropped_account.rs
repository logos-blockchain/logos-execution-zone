use lee_core::program::{
    AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
    respond_unsupported_call,
};

type Instruction = ();

/// Silently drops the second account entirely from its own output: given two `pre_states`, it
/// returns only one `AccountStateDiff`, echoing the first account back unchanged.
fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            ..
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let Ok([pre1, _pre2]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![AccountStateDiff::unchanged(pre1)],
    )
    .write();
}
