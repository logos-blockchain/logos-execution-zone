use lee_core::{
    account::{AccountId, AccountInput, ProgramShardSelector},
    program::{AccountStateDiff, ChainedCall},
};
use token_core::TokenHolding;

pub fn transfer_from_associated_token_account(
    owner: AccountInput,
    sender_ata: AccountInput,
    recipient: AccountInput,
    self_account_id: AccountId,
    token_program_id: AccountId,
    amount: u128,
) -> (Vec<AccountStateDiff>, Vec<ChainedCall>) {
    assert!(owner.is_authorized, "Owner authorization is missing");
    let definition_id = TokenHolding::try_from(sender_ata.shard_of(token_program_id))
        .expect("Sender ATA must hold a valid token")
        .definition_id();
    let seed = associated_token_account_core::verify_ata_and_get_seed(
        &sender_ata,
        &owner,
        definition_id,
        self_account_id,
        token_program_id,
    );

    let transfer_shard_selectors = vec![
        ProgramShardSelector::from(&sender_ata),
        ProgramShardSelector::from(&recipient),
    ];
    let post_diffs = vec![
        AccountStateDiff::unchanged(owner),
        AccountStateDiff::unchanged(sender_ata),
        AccountStateDiff::unchanged(recipient),
    ];
    let chained_call = ChainedCall::new(
        token_program_id,
        transfer_shard_selectors,
        &token_core::Instruction::Transfer {
            amount_to_transfer: amount,
        },
    )
    .with_pda_seeds(vec![seed]);
    (post_diffs, vec![chained_call])
}
