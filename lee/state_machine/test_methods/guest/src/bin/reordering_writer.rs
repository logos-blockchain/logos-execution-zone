use lee_core::{
    account::ShardData,
    program::{Plan, ProgramCall, apply_write, read_program_call},
};

/// Writes its own shard on both accounts, emitting the second handle's effect first — effects
/// are applied in emission order, which need not follow the order of the handles.
type Instruction = Vec<u8>;

fn main() {
    match read_program_call::<Instruction>() {
        ProgramCall::Plan(input, instruction) => {
            let Ok([first, second]) = <[_; 2]>::try_from(input.accounts.clone()) else {
                return;
            };
            let mut plan = Plan::new(&input);
            plan.effect(&second, &Vec::<u8>::new());
            plan.effect(&first, &instruction);
            plan.write()
        }
        ProgramCall::Apply(input) => {
            let written: Vec<u8> = borsh::from_slice(&input.effect_data)
                .expect("reordering_writer wrote its own effect");
            let data = if written.is_empty() {
                ShardData::empty()
            } else {
                written
                    .try_into()
                    .expect("written data fits the data limit")
            };
            apply_write(input, data)
        }
    }
}
