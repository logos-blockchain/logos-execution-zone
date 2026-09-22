use lee_core::{
    account::ProgramShardSelector,
    native_token::{Instruction as NativeInstruction, NATIVE_TOKEN_PROGRAM_ID},
    program::{ChainedCall, LeeCall, Plan, read_lee_call, resolve_write},
};

type Instruction = (Vec<u8>, u128);

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => {
            let (own_data, amount) = input.instruction.clone();
            let Ok([own, sender, recipient]) = <[_; 3]>::try_from(input.accounts.clone()) else {
                panic!("expected exactly 3 handles: [own shard, sender balance, recipient balance]")
            };

            let mut plan = Plan::new(&input, instruction_data);
            plan.update(&own, &own_data);
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
        LeeCall::Resolve(input) => {
            let written: Vec<u8> =
                borsh::from_slice(&input.effect_data).expect("native_spender wrote its own effect");
            let data = written
                .try_into()
                .expect("written data fits the data limit");
            resolve_write(input, data)
        }
    }
}
