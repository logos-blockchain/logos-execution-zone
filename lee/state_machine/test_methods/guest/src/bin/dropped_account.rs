use lee_core::program::{GuestOutput, LeeCall, ProgramOutput, read_lee_call};

type Instruction = ();

/// Silently drops the second handle from its own output: given two, it echoes only the first.
/// Hand-rolls its output because `Plan` copies the complete handle echo out of the input and so
/// cannot under-report by accident.
fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("dropped_account emits no effect to resolve")
    };

    let Ok([first, _second]) = <[_; 2]>::try_from(input.accounts) else {
        return;
    };

    GuestOutput::Execute(ProgramOutput::new(
        input.self_account_id,
        input.caller_account_id,
        instruction_data,
        vec![first],
    ))
    .write();
}
