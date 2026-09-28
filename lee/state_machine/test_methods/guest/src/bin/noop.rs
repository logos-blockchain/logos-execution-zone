use lee_core::program::{Plan, ProgramCall, read_program_call};

type Instruction = ();

fn main() {
    let ProgramCall::Plan(input, ()) = read_program_call::<Instruction>() else {
        panic!("noop emits no effect to apply")
    };

    Plan::new(&input).write();
}
