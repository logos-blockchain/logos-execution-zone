use nssa_core::{
    account::AccountWithMetadata,
    program::{AccountPostState, ChainedCall, ProgramId},
};
use token_core::TokenHolding;

pub fn transfer_from_associated_token_account(
    owner: AccountWithMetadata,
    sender_ata: AccountWithMetadata,
    recipient: AccountWithMetadata,
    ata_program_id: ProgramId,
    amount: u128,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    let token_program_id = sender_ata.account.program_owner;
    assert!(owner.is_authorized, "Owner authorization is missing");
    let definition_id = TokenHolding::try_from(&sender_ata.account.data)
        .expect("Sender ATA must hold a valid token")
        .definition_id();
    let seed =
        ata_core::verify_ata_and_get_seed(&sender_ata, &owner, definition_id, ata_program_id);

    let post_states = vec![
        AccountPostState::new(owner.account.clone()),
        AccountPostState::new(sender_ata.account.clone()),
        AccountPostState::new(recipient.account.clone()),
    ];
    let mut sender_ata_auth = sender_ata.clone();
    sender_ata_auth.is_authorized = true;

    let chained_call = ChainedCall::new(
        token_program_id,
        vec![sender_ata_auth, recipient.clone()],
        &token_core::Instruction::Transfer {
            amount_to_transfer: amount,
        },
    )
    .with_pda_seeds(vec![seed]);
    (post_states, vec![chained_call])
}
