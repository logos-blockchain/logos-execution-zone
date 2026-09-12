use lee_core::{
    account::{AccountId, BalanceDiff, ShardData},
    program::{AccountInput, AccountStateDiff},
};
use token_core::{HoldingTarget, TokenDefinition, TokenHolding};

#[must_use]
pub fn initialize_account(
    definition_account: &AccountInput,
    account_to_initialize: &AccountInput,
    holder: &HoldingTarget,
    self_account_id: AccountId,
) -> Vec<AccountStateDiff> {
    let definition = TokenDefinition::try_from(definition_account.shard_of(self_account_id))
        .expect("Definition account must be valid");
    let holding =
        TokenHolding::zeroized_from_definition(definition_account.account_id, &definition);
    token_core::verify_holding(
        holder,
        account_to_initialize,
        self_account_id,
        definition_account.account_id,
        holding.kind(),
    );

    let shard = account_to_initialize.shard_of(self_account_id);
    let holding_diff = if shard.is_empty() {
        AccountStateDiff::new(
            account_to_initialize.clone(),
            BalanceDiff::Add(0),
            ShardData::from(&holding),
        )
    } else {
        let existing = TokenHolding::try_from(shard).expect("Token Holding account must be valid");
        assert_eq!(
            TokenHolding::zeroized_clone_from(&existing),
            holding,
            "Initialized holding does not match the definition"
        );
        AccountStateDiff::unchanged(account_to_initialize.clone())
    };

    vec![
        AccountStateDiff::unchanged(definition_account.clone()),
        holding_diff,
    ]
}
