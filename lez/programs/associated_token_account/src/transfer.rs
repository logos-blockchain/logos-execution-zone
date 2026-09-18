use lee_core::{
    account::{AccountId, AccountWithMetadata},
    program::{AccountStateDiff, ChainedCall},
};
use token_core::TokenHolding;

pub fn transfer_from_associated_token_account(
    owner: AccountWithMetadata,
    sender_ata: AccountWithMetadata,
    recipient: AccountWithMetadata,
    ata_program_id: AccountId,
    amount: u128,
) -> (Vec<AccountStateDiff>, Vec<ChainedCall>) {
    let token_program_id: AccountId = sender_ata.account.program_owner;
    assert!(owner.is_authorized, "Owner authorization is missing");
    let definition_id = TokenHolding::try_from(&sender_ata.account.data)
        .expect("Sender ATA must hold a valid token")
        .definition_id();
    let seed = associated_token_account_core::verify_ata_and_get_seed(
        &sender_ata,
        &owner,
        definition_id,
        ata_program_id,
    );

    let post_diffs = vec![
        AccountStateDiff::unchanged(owner.clone()),
        AccountStateDiff::unchanged(sender_ata.clone()),
        AccountStateDiff::unchanged(recipient.clone()),
    ];
    let chained_call = ChainedCall::new(
        token_program_id,
        vec![sender_ata.account_id, recipient.account_id],
        &token_core::Instruction::Transfer {
            amount_to_transfer: amount,
        },
    )
    .with_pda_seeds(vec![seed]);
    (post_diffs, vec![chained_call])
}
