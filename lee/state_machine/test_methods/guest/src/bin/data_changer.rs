use lee_core::program::{LeeCall, Plan, read_lee_call, resolve_write};

type Instruction = Vec<u8>;

/// A program that sets its shard's bytes to the ones sent in the instruction.
fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => {
            let Ok([account]) = <[_; 1]>::try_from(input.accounts.clone()) else {
                panic!("data_changer requires exactly 1 account");
            };
            let mut plan = Plan::new(&input, instruction_data);
            plan.update(&account, &input.instruction);
            plan.write()
        }
        LeeCall::Resolve(input) => {
            let written: Vec<u8> =
                borsh::from_slice(&input.effect_data).expect("data_changer wrote its own effect");
            let data = written
                .try_into()
                .expect("written data fits the data limit");
            resolve_write(input, data)
        }
    }
}
