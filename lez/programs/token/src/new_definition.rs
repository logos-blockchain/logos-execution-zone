use lee_core::{
    account::{Account, AccountDiff, AccountWithMetadata, BalanceDiff, Data},
    program::{AccountDiffOutput, Claim},
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
) -> Vec<AccountDiffOutput> {
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

    vec![
        AccountDiffOutput::new_claimed(
            AccountDiff {
                id: definition_target_account.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: Some(Data::from(&token_definition).as_ref().to_vec()),
            },
            Claim::Authorized,
        ),
        AccountDiffOutput::new_claimed(
            AccountDiff {
                id: holding_target_account.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: Some(Data::from(&token_holding).as_ref().to_vec()),
            },
            Claim::Authorized,
        ),
    ]
}

#[must_use]
pub fn new_definition_with_metadata(
    definition_target_account: &AccountWithMetadata,
    holding_target_account: &AccountWithMetadata,
    metadata_target_account: &AccountWithMetadata,
    new_definition: NewTokenDefinition,
    metadata: NewTokenMetadata,
) -> Vec<AccountDiffOutput> {
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

    vec![
        AccountDiffOutput::new_claimed(
            AccountDiff {
                id: definition_target_account.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: Some(Data::from(&token_definition).as_ref().to_vec()),
            },
            Claim::Authorized,
        ),
        AccountDiffOutput::new_claimed(
            AccountDiff {
                id: holding_target_account.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: Some(Data::from(&token_holding).as_ref().to_vec()),
            },
            Claim::Authorized,
        ),
        AccountDiffOutput::new_claimed(
            AccountDiff {
                id: metadata_target_account.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: Some(Data::from(&token_metadata).as_ref().to_vec()),
            },
            Claim::Authorized,
        ),
    ]
}
