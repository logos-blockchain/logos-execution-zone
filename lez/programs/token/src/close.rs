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

    // A slot carrying no data holds no token — a stranger's bare credit can bring one into
    // existence — so there is nothing to decode and nothing to lose by dropping it.
    let data = holding_account.account.data(self_program_id);
    if !data.is_empty() {
        let holding = TokenHolding::try_from(data).expect("Invalid holding data");
        assert!(holding.is_empty(), "Only an empty holding can be closed");
    }

    let mut holding_post = holding_account.account;
    holding_post.slot_mut(self_program_id).data = Data::empty();
    holding_post.prune();

    vec![holding_post]
}
