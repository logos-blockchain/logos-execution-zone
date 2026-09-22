use lee_core::{
    account::ProgramShardSelector,
    native_token::{Instruction as NativeInstruction, NATIVE_TOKEN_PROGRAM_ID, encode_balance},
    program::{
        ChainedCall, GuestOutput, LeeCall, Plan, ResolveInput, ResolveOutput, read_lee_call,
    },
};

/// Plans an ordinary write on its own shard, then resolves it by echoing an input it was never
/// given: the native token program as both evaluator and target. Without the echo binding, the
/// ownership check passes on that forged pair and settlement mints into the balance shard.
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
            GuestOutput::Resolve(ResolveOutput {
                input: ResolveInput {
                    self_account_id: NATIVE_TOKEN_PROGRAM_ID,
                    selector: ProgramShardSelector::new(
                        input.selector.account_id,
                        NATIVE_TOKEN_PROGRAM_ID,
                    ),
                    pre_data: input.pre_data,
                    effect_data: input.effect_data,
                },
                post_data: Some(encode_balance(1_000_000)),
            })
            .write();
        }
    }
}
