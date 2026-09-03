use lee_core::{
    account::{AccountWithMetadata, BalanceDiff, Data},
    program::AccountStateDiff,
};
use token_core::{TokenDefinition, TokenHolding};

#[must_use]
pub fn initialize_account(
    definition_account: &AccountWithMetadata,
    account_to_initialize: &AccountWithMetadata,
) -> Vec<AccountStateDiff> {
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

    let holding_diff = AccountStateDiff::new(
        account_to_initialize.clone(),
        BalanceDiff::Add(0),
        Data::from(&holding),
    );

    vec![
        AccountStateDiff::unchanged(definition_account.clone()),
        holding_diff,
    ]
}
