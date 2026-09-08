use lee_core::{
    account::{AccountId, AccountInput, BalanceDiff, Data},
    program::AccountStateDiff,
};
use token_core::{
    NewTokenDefinition, NewTokenMetadata, TokenDefinition, TokenHolding, TokenMetadata,
};

#[must_use]
pub fn new_fungible_definition(
    definition_target_account: &AccountInput,
    holding_target_account: &AccountInput,
    self_account_id: AccountId,
    name: String,
    total_supply: u128,
) -> Vec<AccountStateDiff> {
    assert!(
        definition_target_account
            .shard_of(self_account_id)
            .is_empty(),
        "Definition target account must not already hold data"
    );

    assert!(
        holding_target_account.shard_of(self_account_id).is_empty(),
        "Holding target account must not already hold data"
    );

    let token_definition = TokenDefinition::Fungible {
        name,
        total_supply,
        metadata_id: None,
    };
    let token_holding = TokenHolding::Fungible {
        definition_id: definition_target_account.account_id,
        balance: total_supply,
    };

    let definition_diff = AccountStateDiff::new(
        definition_target_account.clone(),
        BalanceDiff::Add(0),
        Data::from(&token_definition),
    );

    let holding_diff = AccountStateDiff::new(
        holding_target_account.clone(),
        BalanceDiff::Add(0),
        Data::from(&token_holding),
    );

    vec![definition_diff, holding_diff]
}

#[must_use]
pub fn new_definition_with_metadata(
    definition_target_account: &AccountInput,
    holding_target_account: &AccountInput,
    metadata_target_account: &AccountInput,
    self_account_id: AccountId,
    new_definition: NewTokenDefinition,
    metadata: NewTokenMetadata,
) -> Vec<AccountStateDiff> {
    assert!(
        definition_target_account
            .shard_of(self_account_id)
            .is_empty(),
        "Definition target account must not already hold data"
    );

    assert!(
        holding_target_account.shard_of(self_account_id).is_empty(),
        "Holding target account must not already hold data"
    );

    assert!(
        metadata_target_account.shard_of(self_account_id).is_empty(),
        "Metadata target account must not already hold data"
    );

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

    let definition_diff = AccountStateDiff::new(
        definition_target_account.clone(),
        BalanceDiff::Add(0),
        Data::from(&token_definition),
    );

    let holding_diff = AccountStateDiff::new(
        holding_target_account.clone(),
        BalanceDiff::Add(0),
        Data::from(&token_holding),
    );

    let metadata_diff = AccountStateDiff::new(
        metadata_target_account.clone(),
        BalanceDiff::Add(0),
        Data::from(&token_metadata),
    );

    vec![definition_diff, holding_diff, metadata_diff]
}
