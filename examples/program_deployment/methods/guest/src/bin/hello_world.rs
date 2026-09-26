use lee_core::{
    account::ShardData,
    program::{Plan, PlanInput, run_program},
};

// Hello-world example program.
//
// This program reads an arbitrary sequence of bytes as its instruction
// and appends those bytes to this program's own shard on the single input account.

type Instruction = Vec<u8>;

fn main() {
    run_program(plan, apply)
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "run_program passes the decoded instruction by value; this planner only reads it"
)]
fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    let mut plan = Plan::new(input);
    let [account] = input.accounts.as_slice() else {
        panic!("Input accounts should consist of a single account");
    };
    plan.effect(account, &instruction);
    plan
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "run_program's apply returns None to keep a shard"
)]
fn apply(greeting: Vec<u8>, pre_data: &ShardData) -> Option<Vec<u8>> {
    let mut bytes = pre_data.clone().into_inner();
    bytes.extend(greeting);
    Some(bytes)
}
