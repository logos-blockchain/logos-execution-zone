use lee_core::{
    account::{Account, AccountWithMetadata, Data},
    program::ProgramId,
};
use token_core::TokenHolding;

#[must_use]
pub fn close_holding(
    holding_account: AccountWithMetadata,
    self_program_id: ProgramId,
) -> Vec<Account> {
    assert!(
        holding_account.is_authorized,
        "Holding authorization is missing"
    );

    let holding = TokenHolding::try_from(holding_account.account.data(self_program_id))
        .expect("Invalid holding data");
    assert!(holding.is_empty(), "Only an empty holding can be closed");

    let mut holding_post = holding_account.account;
    holding_post.slot_mut(self_program_id).data = Data::empty();
    holding_post.prune();

    vec![holding_post]
}
