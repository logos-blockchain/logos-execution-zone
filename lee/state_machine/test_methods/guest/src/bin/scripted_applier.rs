use lee_core::{
    account::ShardData,
    program::{Plan, PlanInput, run_program},
};

// Each effect carries the output it asks for, so a test can drive the runner's Keep, Clear
// and Write arms directly.
fn main() {
    run_program(
        |input: &PlanInput, (): ()| Plan::new(input),
        |post_data: Option<Vec<u8>>, _pre_data: &ShardData| post_data,
    )
}
