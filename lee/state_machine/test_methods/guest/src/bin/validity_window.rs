use lee_core::program::{
    BlockValidityWindow, LeeCall, Plan, TimestampValidityWindow, read_lee_call,
};

type Instruction = (BlockValidityWindow, TimestampValidityWindow);

fn main() {
    let LeeCall::Execute(input, instruction_data) = read_lee_call::<Instruction>() else {
        panic!("validity_window emits no effect to resolve")
    };
    let (block_validity_window, timestamp_validity_window) = input.instruction;

    let Ok([_account]) = <[_; 1]>::try_from(input.accounts.clone()) else {
        return;
    };

    let mut plan = Plan::new(&input, instruction_data);
    plan.block_window(block_validity_window);
    plan.timestamp_window(timestamp_validity_window);
    plan.write()
}
