use lee_core::{
    account::{AccountId, AccountInput, Data, ProgramShardSelector},
    program::{AccountStateDiff, ChainedCall},
};
use token_core::{TokenDefinition, TokenHolding};

pub fn create_associated_token_account(
    owner: AccountInput,
    token_definition: AccountInput,
    ata_account: AccountInput,
    self_account_id: AccountId,
    token_program_id: AccountId,
) -> (Vec<AccountStateDiff>, Vec<ChainedCall>) {
    let ata_seed = associated_token_account_core::verify_ata_and_get_seed(
        &ata_account,
        &owner,
        token_definition.account_id,
        self_account_id,
        token_program_id,
    );

    let ata_shard = ata_account.shard_of(token_program_id);
    let needs_initialize = if ata_shard.is_empty() {
        true
    } else if holds_intended_asset(ata_shard, &token_definition, token_program_id) {
        false
    } else {
        assert!(owner.is_authorized, "Owner authorization is missing");
        true
    };

    let chained_calls = if needs_initialize {
        vec![
            ChainedCall::new(
                token_program_id,
                vec![
                    ProgramShardSelector::from(&token_definition),
                    ProgramShardSelector::from(&ata_account),
                ],
                &token_core::Instruction::InitializeAccount,
            )
            .with_pda_seeds(vec![ata_seed]),
        ]
    } else {
        vec![]
    };

    let post_diffs = vec![
        AccountStateDiff::unchanged(owner),
        AccountStateDiff::unchanged(token_definition),
        AccountStateDiff::unchanged(ata_account),
    ];

    (post_diffs, chained_calls)
}

fn holds_intended_asset(
    shard: &Data,
    token_definition: &AccountInput,
    token_program_id: AccountId,
) -> bool {
    let Ok(holding) = TokenHolding::try_from(shard) else {
        return false;
    };
    let Ok(definition) = TokenDefinition::try_from(token_definition.shard_of(token_program_id))
    else {
        return false;
    };
    holding.definition_id() == token_definition.account_id
        && matches!(
            (holding, definition),
            (
                TokenHolding::Fungible { .. },
                TokenDefinition::Fungible { .. }
            ) | (
                TokenHolding::NftMaster { .. } | TokenHolding::NftPrintedCopy { .. },
                TokenDefinition::NonFungible { .. }
            )
        )
}
