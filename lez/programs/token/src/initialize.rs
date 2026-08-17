use lee_core::{
    account::{Account, AccountDiff, AccountWithMetadata, BalanceDiff, Data},
    program::{AccountDiffOutput, Claim},
};
use token_core::{TokenDefinition, TokenHolding};

#[must_use]
pub fn initialize_account(
    definition_account: AccountWithMetadata,
    account_to_initialize: AccountWithMetadata,
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

    vec![
        AccountDiffOutput::new(AccountDiff {
            id: definition_account.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: None,
        }),
        AccountDiffOutput::new_claimed(
            AccountDiff {
                id: account_to_initialize.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: Some(Data::from(&holding).as_ref().to_vec()),
            },
            Claim::Authorized,
        ),
    ]
}
