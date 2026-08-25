use lee_core::{
    account::{Account, AccountWithMetadata},
    program::{ChainedCall, ProgramId},
};
use token_core::TokenHolding;

pub fn burn_from_associated_token_account(
    owner: AccountWithMetadata,
    holder_ata: AccountWithMetadata,
    token_definition: AccountWithMetadata,
    ata_program_id: ProgramId,
    token_program_id: ProgramId,
    amount: u128,
) -> (Vec<Account>, Vec<ChainedCall>) {
    assert!(owner.is_authorized, "Owner authorization is missing");
    let definition_id = TokenHolding::try_from(holder_ata.account.data(token_program_id))
        .expect("Holder ATA must hold a valid token")
        .definition_id();
    let seed = associated_token_account_core::verify_ata_and_get_seed(
        &holder_ata,
        &owner,
        definition_id,
        ata_program_id,
    );

    let post_states = vec![
        owner.account.clone(),
        holder_ata.account.clone(),
        token_definition.account.clone(),
    ];

    let chained_call = ChainedCall::new(
        token_program_id,
        vec![token_definition, holder_ata],
        &token_core::Instruction::Burn {
            amount_to_burn: amount,
        },
    )
    .with_pda_seeds(vec![seed]);

    (post_states, vec![chained_call])
}
