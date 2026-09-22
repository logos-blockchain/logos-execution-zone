use lee_core::program::{LeeCall, Plan, read_lee_call, resolve_write};

/// Writes to the first handle's selected shard whoever owns it. When that shard belongs to
/// another program the resolution is rejected as a foreign write.
type Instruction = Vec<u8>;

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => {
            let Ok([target, _other]) = <[_; 2]>::try_from(input.accounts.clone()) else {
                return;
            };
            let mut plan = Plan::new(&input, instruction_data);
            plan.update(&target, &input.instruction);
            plan.write()
        }
        LeeCall::Resolve(input) => {
            let written: Vec<u8> = borsh::from_slice(&input.effect_data)
                .expect("foreign_shard_writer wrote its own effect");
            let data = written
                .try_into()
                .expect("written data fits the data limit");
            resolve_write(input, data)
        }
    }
}
