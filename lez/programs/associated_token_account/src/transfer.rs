use lee_core::{
    account::{AccountDiff, AccountWithMetadata},
    program::{AccountDiffOutput, ChainedCall, ProgramId},
};
use token_core::TokenHolding;

pub fn transfer_from_associated_token_account(
    owner: AccountWithMetadata,
    sender_ata: AccountWithMetadata,
    recipient: AccountWithMetadata,
    ata_program_id: ProgramId,
    amount: u128,
) -> (Vec<AccountDiffOutput>, Vec<ChainedCall>) {
    let token_program_id: lee_core::program::ProgramId = sender_ata.account.program_owner.into();
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

    let post_states = vec![
        AccountDiffOutput::new(AccountDiff::unchanged(owner.account_id)),
        AccountDiffOutput::new(AccountDiff::unchanged(sender_ata.account_id)),
        AccountDiffOutput::new(AccountDiff::unchanged(recipient.account_id)),
    ];
    let chained_call = ChainedCall::new(
        token_program_id,
        vec![sender_ata.account_id, recipient.account_id],
        &token_core::Instruction::Transfer {
            amount_to_transfer: amount,
        },
    )
    .with_pda_seeds(vec![seed]);
    (post_states, vec![chained_call])
}
