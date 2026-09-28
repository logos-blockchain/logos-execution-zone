use associated_token_account_core::AtaContents;
use lee_core::{
    account::{AccountId, ProgramShardSelector, ShardData},
    program::{AccountMeta, ChainedCall, Plan, PlanInput},
};
use token_core::{TokenDefinition, TokenDescriptor, TokenKind};

use crate::Effect;

pub fn create_associated_token_account(
    input: &PlanInput,
    token_program_id: AccountId,
    kind: TokenKind,
    contents: AtaContents,
) -> Plan {
    let [owner, token_definition, ata_account] =
        <&[AccountMeta; 3]>::try_from(input.accounts.as_slice())
            .expect("Create instruction requires exactly three accounts");
    let ata_seed = associated_token_account_core::verify_ata_and_get_seed(
        ata_account,
        owner,
        token_definition.account_id,
        input.self_account_id,
        token_program_id,
    );

    let mut plan = Plan::new(input);

    // Taking `contents` on the caller's word is a hole, not a shortcut: `Empty` claimed over a
    // funded ATA hands the token program a seed-authorized `InitializeAccount` and zeroizes the
    // holding, with no owner signature anywhere. Token's own `InitializeHolding` does not stop
    // it, because the seed is exactly what makes that account authorized in the child call.
    plan.inspect(
        ata_account,
        token_program_id,
        &Effect::AtaContents {
            descriptor: TokenDescriptor {
                definition_id: token_definition.account_id,
                kind,
            },
            contents,
        },
    );

    let needs_initialize = match contents {
        AtaContents::Empty => true,
        AtaContents::Intended => {
            // The only branch with no child call, so the only one where nothing downstream
            // pins `kind` to the definition it was classified against. The other two leave
            // that to `InitializeAccount`'s `CheckHoldingKind` effect on this same shard.
            plan.inspect(
                token_definition,
                token_program_id,
                &Effect::DefinitionKind { kind },
            );
            false
        }
        AtaContents::Squatted => {
            assert!(owner.is_authorized, "Owner authorization is missing");
            true
        }
    };

    if needs_initialize {
        plan.call(
            ChainedCall::new(
                token_program_id,
                vec![
                    ProgramShardSelector::from(token_definition),
                    ProgramShardSelector::from(ata_account),
                ],
                &token_core::Instruction::InitializeAccount { kind },
            )
            .with_pda_seeds(vec![ata_seed]),
        );
    }
    plan
}

pub fn check_contents(pre_data: &ShardData, descriptor: &TokenDescriptor, contents: AtaContents) {
    assert_eq!(
        associated_token_account_core::classify(pre_data, descriptor),
        contents,
        "Associated token account does not hold what the instruction claims"
    );
}

pub fn check_definition_kind(pre_data: &ShardData, kind: TokenKind) {
    let definition =
        TokenDefinition::try_from(pre_data).expect("Token Definition account must be valid");
    assert_eq!(
        TokenKind::from_definition(&definition),
        kind,
        "Token Definition does not initialize this Token Holding kind"
    );
}
