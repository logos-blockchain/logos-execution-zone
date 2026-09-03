use lee_core::program::{
    AccountStateDiff, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
    respond_unsupported_call,
};

/// Given two `pre_states`, silently drops the second account entirely from its output, echoing
/// only the first account back unchanged. Distinct from `dropped_account` only in name/intent
/// (this one models "forgot" rather than "deliberately drops"); both are caught the same way,
/// by `DeclaredAccountMissingFromOutput`.
type Instruction = ();

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
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
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![AccountStateDiff::unchanged(pre1)],
    )
    .write();
}
