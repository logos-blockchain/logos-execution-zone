use lee_core::program::{GuestOutput, PlanInput, PlanOutput, ProgramCall, read_program_call};

type Instruction = ();

/// Silently drops the second handle from its own output: given two, it echoes only the first.
/// Hand-rolls its output because `Plan` copies the complete handle echo out of the input and so
/// cannot under-report by accident.
fn main() {
    let ProgramCall::Plan(input, ()) = read_program_call::<Instruction>() else {
        panic!("dropped_account emits no effect to apply")
    };

    let Ok([first, _second]) = <[_; 2]>::try_from(input.accounts) else {
        return;
    };

    GuestOutput::Plan(PlanOutput::new(PlanInput {
        accounts: vec![first],
        ..input
    }))
    .write();
}
