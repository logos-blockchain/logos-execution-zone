use lee_core::{
    account::{Data, Input, Slot},
    program::ProgramId,
};
use token_core::TokenHolding;

#[must_use]
pub fn close_holding(holding_account: Input, self_program_id: ProgramId) -> Vec<Option<Slot>> {
    assert!(
        holding_account.is_authorized,
        "Holding authorization is missing"
    );

    // A slot carrying no data holds no token — a stranger's bare credit can bring one into
    // existence — so there is nothing to decode and nothing to lose by dropping it.
    let data = holding_account.data(self_program_id);
    if !data.is_empty() {
        let holding = TokenHolding::try_from(data).expect("Invalid holding data");
        assert!(holding.is_empty(), "Only an empty holding can be closed");
    }

    let mut holding_post = holding_account.into_slot_of(self_program_id);
    holding_post.data = Data::default();

    vec![Some(holding_post)]
}
