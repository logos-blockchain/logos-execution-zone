use lee_core::{
    account::{Account, AccountWithMetadata, BalanceDiff, Data},
    program::{AccountStateDiff, Claim},
};
use token_core::{
    NewTokenDefinition, NewTokenMetadata, TokenDefinition, TokenHolding, TokenMetadata,
};

#[must_use]
pub fn new_fungible_definition(
    definition_target_account: &AccountWithMetadata,
    holding_target_account: &AccountWithMetadata,
    name: String,
    total_supply: u128,
) -> Vec<AccountStateDiff> {
    assert_eq!(
        definition_target_account.account,
        Account::default(),
        "Definition target account must have default values"
    );

    assert_eq!(
        holding_target_account.account,
        Account::default(),
        "Holding target account must have default values"
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

    let definition_diff = AccountStateDiff::new_claimed(
        definition_target_account.clone(),
        BalanceDiff::Add(0),
        Data::from(&token_definition),
        Claim::Authorized,
    );

    let holding_diff = AccountStateDiff::new_claimed(
        holding_target_account.clone(),
        BalanceDiff::Add(0),
        Data::from(&token_holding),
        Claim::Authorized,
    );

    vec![definition_diff, holding_diff]
}

#[must_use]
pub fn new_definition_with_metadata(
    definition_target_account: &AccountWithMetadata,
    holding_target_account: &AccountWithMetadata,
    metadata_target_account: &AccountWithMetadata,
    new_definition: NewTokenDefinition,
    metadata: NewTokenMetadata,
) -> Vec<AccountStateDiff> {
    assert_eq!(
        definition_target_account.account,
        Account::default(),
        "Definition target account must have default values"
    );

    assert_eq!(
        holding_target_account.account,
        Account::default(),
        "Holding target account must have default values"
    );

    assert_eq!(
        metadata_target_account.account,
        Account::default(),
        "Metadata target account must have default values"
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

    let definition_diff = AccountStateDiff::new_claimed(
        definition_target_account.clone(),
        BalanceDiff::Add(0),
        Data::from(&token_definition),
        Claim::Authorized,
    );

    let holding_diff = AccountStateDiff::new_claimed(
        holding_target_account.clone(),
        BalanceDiff::Add(0),
        Data::from(&token_holding),
        Claim::Authorized,
    );

    let metadata_diff = AccountStateDiff::new_claimed(
        metadata_target_account.clone(),
        BalanceDiff::Add(0),
        Data::from(&token_metadata),
        Claim::Authorized,
    );

    vec![definition_diff, holding_diff, metadata_diff]
}
