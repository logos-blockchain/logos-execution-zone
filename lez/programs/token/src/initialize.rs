use lee_core::account::{Account, AccountWithMetadata, Data};
use token_core::{TokenDefinition, TokenHolding};

#[must_use]
pub fn initialize_account(
    definition_account: AccountWithMetadata,
    account_to_initialize: AccountWithMetadata,
) -> Vec<Account> {
    assert!(
        account_to_initialize.account.data.is_empty(),
        "Only Uninitialized accounts can be initialized"
    );

    // TODO: #212 We should check that this is an account owned by the token program.
    // This check can't be done here since the ID of the program is known only after compiling it
    //
    // Check definition account is valid
    let definition = TokenDefinition::try_from(&definition_account.account.data)
        .expect("Definition account must be valid");
    let holding =
        TokenHolding::zeroized_from_definition(definition_account.account_id, &definition);

    let definition_post = definition_account.account;
    let mut account_to_initialize = account_to_initialize.account;
    account_to_initialize.data = Data::from(&holding);

    vec![definition_post, account_to_initialize]
}
