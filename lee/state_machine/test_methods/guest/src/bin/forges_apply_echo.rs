use lee_core::{
    account::ProgramShardSelector,
    native_token::{Instruction as NativeInstruction, NATIVE_TOKEN_PROGRAM_ID, encode_balance},
    program::{
        ApplyInput, ApplyOutput, ChainedCall, GuestOutput, Plan, ProgramCall, read_program_call,
    },
};

/// Selects which input field the guest falsifies in its apply output.
#[derive(Clone, Copy, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum ForgeField {
    /// Claims the native token program as evaluator instead of its own account id.
    SelfId,
    /// Claims the native token program owns the applied shard instead of itself.
    Selector,
    /// Echoes back `pre_data` different from what it was actually given.
    PreData,
    /// Echoes back `effect_data` different from what it actually planned.
    EffectData,
}

type Instruction = (ForgeField, u128);

fn main() {
    match read_program_call::<Instruction>() {
        ProgramCall::Plan(input, instruction) => {
            let (forge_field, amount) = instruction;
            let Ok([own, sender, recipient]) = <[_; 3]>::try_from(input.accounts.clone()) else {
                panic!("expected exactly 3 handles: [own shard, sender balance, recipient balance]")
            };

            let mut plan = Plan::new(&input);
            plan.effect(&own, &forge_field);
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
            let forge_field: ForgeField = borsh::from_slice(&input.effect_data)
                .expect("forges_apply_echo wrote its own effect");
            let forged_input = match forge_field {
                ForgeField::SelfId => ApplyInput {
                    self_account_id: NATIVE_TOKEN_PROGRAM_ID,
                    ..input
                },
                ForgeField::Selector => ApplyInput {
                    selector: ProgramShardSelector::new(
                        input.selector.account_id,
                        NATIVE_TOKEN_PROGRAM_ID,
                    ),
                    ..input
                },
                ForgeField::PreData => ApplyInput {
                    pre_data: encode_balance(0xDEAD_BEEF),
                    ..input
                },
                ForgeField::EffectData => ApplyInput {
                    effect_data: vec![0xFF; 8],
                    ..input
                },
            };
            GuestOutput::Apply(ApplyOutput {
                input: forged_input,
                post_data: Some(encode_balance(1_000_000)),
            })
            .write();
        }
    }
}
