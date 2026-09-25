use lee_core::program::{
    BlockValidityWindow, Plan, ProgramCall, TimestampValidityWindow, read_program_call,
};

type Instruction = (BlockValidityWindow, TimestampValidityWindow);

fn main() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<Instruction>() else {
        panic!("validity_window emits no effect to apply")
    };
    let (block_validity_window, timestamp_validity_window) = instruction;

    let Ok([_account]) = <[_; 1]>::try_from(input.accounts.clone()) else {
        return;
    };

    let mut plan = Plan::new(&input);
    plan.block_window(block_validity_window);
    plan.timestamp_window(timestamp_validity_window);
    plan.write()
}
