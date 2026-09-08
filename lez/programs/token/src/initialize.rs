use lee_core::{
    account::{AccountId, AccountInput, BalanceDiff, Data},
    program::AccountStateDiff,
};
use token_core::{TokenDefinition, TokenHolding};

#[must_use]
pub fn initialize_account(
    definition_account: &AccountInput,
    account_to_initialize: &AccountInput,
    self_account_id: AccountId,
) -> Vec<AccountStateDiff> {
    assert!(
        account_to_initialize.shard_of(self_account_id).is_empty(),
        "Only Uninitialized accounts can be initialized"
    );

    let definition = TokenDefinition::try_from(definition_account.shard_of(self_account_id))
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
