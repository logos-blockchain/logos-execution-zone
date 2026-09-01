use lee_core::account::{Account, AccountWithMetadata, Data};
use token_core::{
    NewTokenDefinition, NewTokenMetadata, TokenDefinition, TokenHolding, TokenMetadata,
};

#[must_use]
pub fn new_fungible_definition(
    definition_target_account: AccountWithMetadata,
    holding_target_account: AccountWithMetadata,
    name: String,
    total_supply: u128,
) -> Vec<Account> {
    assert!(
        definition_target_account.account.data.is_empty(),
        "Definition target account must not already hold data"
    );

    assert!(
        holding_target_account.account.data.is_empty(),
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

    let mut definition_target_account_post = definition_target_account.account;
    definition_target_account_post.data = Data::from(&token_definition);

    let mut holding_target_account_post = holding_target_account.account;
    holding_target_account_post.data = Data::from(&token_holding);

    vec![definition_target_account_post, holding_target_account_post]
}

#[must_use]
pub fn new_definition_with_metadata(
    definition_target_account: AccountWithMetadata,
    holding_target_account: AccountWithMetadata,
    metadata_target_account: AccountWithMetadata,
    new_definition: NewTokenDefinition,
    metadata: NewTokenMetadata,
) -> Vec<Account> {
    assert!(
        definition_target_account.account.data.is_empty(),
        "Definition target account must not already hold data"
    );

    assert!(
        holding_target_account.account.data.is_empty(),
        "Holding target account must not already hold data"
    );

    assert!(
        metadata_target_account.account.data.is_empty(),
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

    let mut definition_target_account_post = definition_target_account.account;
    definition_target_account_post.data = Data::from(&token_definition);

    let mut holding_target_account_post = holding_target_account.account;
    holding_target_account_post.data = Data::from(&token_holding);

    let mut metadata_target_account_post = metadata_target_account.account;
    metadata_target_account_post.data = Data::from(&token_metadata);

    vec![
        definition_target_account_post,
        holding_target_account_post,
        metadata_target_account_post,
    ]
}
