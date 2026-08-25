use lee_core::{
    account::{Account, AccountWithMetadata, Data},
    program::ProgramId,
};
use token_core::{TokenDefinition, TokenHolding};

#[must_use]
pub fn initialize_account(
    definition_account: AccountWithMetadata,
    account_to_initialize: AccountWithMetadata,
    self_program_id: ProgramId,
) -> Vec<Account> {
    assert!(
        account_to_initialize
            .account
            .data(self_program_id)
            .is_empty(),
        "Only Uninitialized accounts can be initialized"
    );

    let definition = TokenDefinition::try_from(definition_account.account.data(self_program_id))
        .expect("Definition account must be valid");
    let holding =
        TokenHolding::zeroized_from_definition(definition_account.account_id, &definition);

    let mut account_to_initialize_post = account_to_initialize.account;
    account_to_initialize_post.slot_mut(self_program_id).data = Data::from(&holding);

    vec![definition_account.account, account_to_initialize_post]
}
