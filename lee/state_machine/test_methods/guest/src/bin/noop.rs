use lee_core::program::{LeeCall, Plan, read_lee_call};

type Instruction = ();

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("noop emits no effect to resolve")
    };

    Plan::new(&input, instruction_data).write();
}
