use lee_core::{
    account::{Data, Input, Slot},
    program::ProgramId,
};
use token_core::{TokenDefinition, TokenHolding};

#[must_use]
pub fn initialize_account(
    definition_account: &Input,
    account_to_initialize: Input,
    self_program_id: ProgramId,
) -> Vec<Option<Slot>> {
    assert!(
        account_to_initialize.data(self_program_id).is_empty(),
        "Only Uninitialized accounts can be initialized"
    );

    let definition = TokenDefinition::try_from(definition_account.data(self_program_id))
        .expect("Definition account must be valid");
    let holding =
        TokenHolding::zeroized_from_definition(definition_account.account_id, &definition);

    let mut account_to_initialize_post = account_to_initialize.into_slot_of(self_program_id);
    account_to_initialize_post.data = Data::from(&holding);

    vec![
        definition_account.unchanged(),
        Some(account_to_initialize_post),
    ]
}
