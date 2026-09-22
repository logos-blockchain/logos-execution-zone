use lee_core::{
    account::ShardData,
    program::{AccountMeta, Plan},
};
use token_core::{
    NewTokenDefinition, NewTokenMetadata, TokenDefinition, TokenHolding, TokenMetadata,
};

use crate::Effect;

pub fn new_fungible_definition(
    plan: &mut Plan,
    definition_target_account: &AccountMeta,
    holding_target_account: &AccountMeta,
    name: String,
    total_supply: u128,
) {
    plan.update(
        definition_target_account,
        &Effect::CreateDefinition(TokenDefinition::Fungible {
            name,
            total_supply,
            metadata_id: None,
        }),
    );
    plan.update(
        holding_target_account,
        &Effect::CreateHolding(TokenHolding::Fungible {
            definition_id: definition_target_account.account_id,
            balance: total_supply,
        }),
    );
}

pub fn new_definition_with_metadata(
    plan: &mut Plan,
    definition_target_account: &AccountMeta,
    holding_target_account: &AccountMeta,
    metadata_target_account: &AccountMeta,
    new_definition: NewTokenDefinition,
    metadata: NewTokenMetadata,
) {
    let (token_definition, token_holding) = match new_definition {
        NewTokenDefinition::Fungible { name, total_supply } => (
            TokenDefinition::Fungible {
                name,
                total_supply,
                metadata_id: Some(metadata_target_account.account_id),
            },
            TokenHolding::Fungible {
                definition_id: definition_target_account.account_id,
                balance: total_supply,
            },
        ),
        NewTokenDefinition::NonFungible {
            name,
            printable_supply,
        } => (
            TokenDefinition::NonFungible {
                name,
                printable_supply,
                metadata_id: metadata_target_account.account_id,
            },
            TokenHolding::NftMaster {
                definition_id: definition_target_account.account_id,
                print_balance: printable_supply,
            },
        ),
    };

    let token_metadata = TokenMetadata {
        definition_id: definition_target_account.account_id,
        standard: metadata.standard,
        uri: metadata.uri,
        creators: metadata.creators,
        primary_sale_date: 0_u64, // TODO #261: future works to implement this
    };

    plan.update(
        definition_target_account,
        &Effect::CreateDefinition(token_definition),
    );
    plan.update(
        holding_target_account,
        &Effect::CreateHolding(token_holding),
    );
    plan.update(
        metadata_target_account,
        &Effect::CreateMetadata(token_metadata),
    );
}

#[must_use]
pub fn create_definition(pre_data: &ShardData, definition: &TokenDefinition) -> ShardData {
    assert!(
        pre_data.is_empty(),
        "Definition target account must not already hold data"
    );

    ShardData::from(definition)
}

#[must_use]
pub fn create_holding(pre_data: &ShardData, holding: &TokenHolding) -> ShardData {
    assert!(
        pre_data.is_empty(),
        "Holding target account must not already hold data"
    );

    ShardData::from(holding)
}

#[must_use]
pub fn create_metadata(pre_data: &ShardData, metadata: &TokenMetadata) -> ShardData {
    assert!(
        pre_data.is_empty(),
        "Metadata target account must not already hold data"
    );

    ShardData::from(metadata)
}
