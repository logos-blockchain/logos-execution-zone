use lee_core::{
    account::{Input, Slot},
    program::{ChainedCall, ProgramId},
};
use token_core::TokenHolding;

pub fn transfer_from_associated_token_account(
    owner: Input,
    sender_ata: Input,
    recipient: Input,
    ata_program_id: ProgramId,
    token_program_id: ProgramId,
    amount: u128,
) -> (Vec<Option<Slot>>, Vec<ChainedCall>) {
    assert!(owner.is_authorized, "Owner authorization is missing");
    let definition_id = TokenHolding::try_from(sender_ata.data(token_program_id))
        .expect("Sender ATA must hold a valid token")
        .definition_id();
    let seed = associated_token_account_core::verify_ata_and_get_seed(
        &sender_ata,
        &owner,
        definition_id,
        ata_program_id,
    );

    let post_states = vec![
        owner.unchanged(),
        sender_ata.unchanged(),
        recipient.unchanged(),
    ];

    let mut sender_ata_auth = sender_ata;
    sender_ata_auth.is_authorized = true;

    let chained_call = ChainedCall::new(
        token_program_id,
        vec![sender_ata_auth, recipient],
        &token_core::Instruction::Transfer {
            amount_to_transfer: amount,
        },
    )
    .with_pda_seeds(vec![seed]);

    (post_states, vec![chained_call])
}
