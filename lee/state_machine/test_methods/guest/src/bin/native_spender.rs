use lee_core::{
    account::ProgramShardSelector,
    native_token::{Instruction as NativeInstruction, NATIVE_TOKEN_PROGRAM_ID},
    program::{ChainedCall, Plan, ProgramCall, apply_write, read_program_call},
};

type Instruction = (Vec<u8>, u128);

fn main() {
    match read_program_call::<Instruction>() {
        ProgramCall::Plan(input, instruction) => {
            let (own_data, amount) = instruction;
            let Ok([own, sender, recipient]) = <[_; 3]>::try_from(input.accounts.clone()) else {
                panic!("expected exactly 3 handles: [own shard, sender balance, recipient balance]")
            };

            let mut plan = Plan::new(&input);
            plan.effect(&own, &own_data);
            plan.call(ChainedCall::new(
                NATIVE_TOKEN_PROGRAM_ID,
                vec![
                    ProgramShardSelector::from(&sender),
                    ProgramShardSelector::from(&recipient),
                ],
                &NativeInstruction::Transfer { amount },
            ));
            plan.write()
        }
        ProgramCall::Apply(input) => {
            let written: Vec<u8> =
                borsh::from_slice(&input.effect_data).expect("native_spender wrote its own effect");
            let data = written
                .try_into()
                .expect("written data fits the data limit");
            apply_write(input, data)
        }
    }
}
