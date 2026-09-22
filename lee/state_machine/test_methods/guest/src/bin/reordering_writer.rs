use lee_core::{
    account::ShardData,
    program::{LeeCall, Plan, read_lee_call, resolve_write},
};

/// Writes its own shard on both accounts, emitting the second handle's effect first — effects
/// are resolved in emission order, which need not follow the order of the handles.
type Instruction = Vec<u8>;

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => {
            let Ok([first, second]) = <[_; 2]>::try_from(input.accounts.clone()) else {
                return;
            };
            let mut plan = Plan::new(&input, instruction_data);
            plan.update(&second, &Vec::<u8>::new());
            plan.update(&first, &input.instruction);
            plan.write()
        }
        LeeCall::Resolve(input) => {
            let written: Vec<u8> = borsh::from_slice(&input.effect_data)
                .expect("reordering_writer wrote its own effect");
            let data = if written.is_empty() {
                ShardData::empty()
            } else {
                written
                    .try_into()
                    .expect("written data fits the data limit")
            };
            resolve_write(input, data)
        }
    }
}
