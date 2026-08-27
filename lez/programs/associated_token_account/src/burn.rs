use lee_core::{
    account::AccountWithMetadata,
    program::{AccountDiffOutput, ChainedCall, ProgramId},
};
use token_core::TokenHolding;

pub fn burn_from_associated_token_account(
    owner: &AccountWithMetadata,
    holder_ata: &AccountWithMetadata,
    token_definition: &AccountWithMetadata,
    ata_program_id: ProgramId,
    amount: u128,
) -> (Vec<AccountDiffOutput>, Vec<ChainedCall>) {
    let token_program_id: lee_core::program::ProgramId = holder_ata.account.program_owner.into();
    assert!(owner.is_authorized, "Owner authorization is missing");
    let definition_id = TokenHolding::try_from(&holder_ata.account.data)
        .expect("Holder ATA must hold a valid token")
        .definition_id();
    let seed = associated_token_account_core::verify_ata_and_get_seed(
        holder_ata,
        owner,
        definition_id,
        ata_program_id,
    );

    let post_states = vec![
        AccountDiffOutput::unchanged(owner.account_id),
        AccountDiffOutput::unchanged(holder_ata.account_id),
        AccountDiffOutput::unchanged(token_definition.account_id),
    ];
    let chained_call = ChainedCall::new(
        token_program_id,
        vec![token_definition.account_id, holder_ata.account_id],
        &token_core::Instruction::Burn {
            amount_to_burn: amount,
        },
    )
    .with_pda_seeds(vec![seed]);
    (post_states, vec![chained_call])
}
