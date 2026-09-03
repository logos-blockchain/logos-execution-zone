use lee_core::{
    account::{Account, AccountWithMetadata, BalanceDiff, Data},
    program::{AccountStateDiff, Claim},
};
use token_core::{TokenDefinition, TokenHolding};

#[must_use]
pub fn initialize_account(
    definition_account: &AccountWithMetadata,
    account_to_initialize: &AccountWithMetadata,
) -> Vec<AccountStateDiff> {
    assert_eq!(
        account_to_initialize.account,
        Account::default(),
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

    let holding_diff = AccountStateDiff::new_claimed(
        account_to_initialize.clone(),
        BalanceDiff::Add(0),
        Data::from(&holding),
        Claim::Authorized,
    );

    vec![
        AccountStateDiff::unchanged(definition_account.clone()),
        holding_diff,
    ]
}
