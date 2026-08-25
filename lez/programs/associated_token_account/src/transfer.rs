use lee_core::{
    account::{Account, AccountWithMetadata},
    program::{ChainedCall, ProgramId},
};
use token_core::TokenHolding;

pub fn transfer_from_associated_token_account(
    owner: AccountWithMetadata,
    sender_ata: AccountWithMetadata,
    recipient: AccountWithMetadata,
    ata_program_id: ProgramId,
    token_program_id: ProgramId,
    amount: u128,
) -> (Vec<Account>, Vec<ChainedCall>) {
    assert!(owner.is_authorized, "Owner authorization is missing");
    let definition_id = TokenHolding::try_from(sender_ata.account.data(token_program_id))
        .expect("Sender ATA must hold a valid token")
        .definition_id();
    let seed = associated_token_account_core::verify_ata_and_get_seed(
        &sender_ata,
        &owner,
        definition_id,
        ata_program_id,
    );

    let post_states = vec![
        owner.account.clone(),
        sender_ata.account.clone(),
        recipient.account.clone(),
    ];

    let chained_call = ChainedCall::new(
        token_program_id,
        vec![sender_ata, recipient],
        &token_core::Instruction::Transfer {
            amount_to_transfer: amount,
            sender_seed: Some(seed),
        },
    );

    (post_states, vec![chained_call])
}
