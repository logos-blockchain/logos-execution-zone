use lee_core::{
    account::{Account, AccountDiff, AccountWithMetadata, BalanceDiff, Data},
    program::{AccountDiffOutput, Claim},
};
use token_core::{TokenDefinition, TokenHolding};

#[must_use]
pub fn initialize_account(
    definition_account: &AccountWithMetadata,
    account_to_initialize: &AccountWithMetadata,
) -> Vec<AccountDiffOutput> {
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

    let holding_diff = AccountDiff {
        id: account_to_initialize.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(Data::from(&holding)),
    };

    vec![
        AccountDiffOutput::unchanged(definition_account.account_id),
        AccountDiffOutput::new_claimed(holding_diff, Claim::Authorized),
    ]
}
