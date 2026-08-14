use lee_core::{
    account::AccountWithMetadata,
    program::{AccountPostState, ChainedCall, ProgramId},
};
use token_core::TokenHolding;

pub fn burn_from_associated_token_account(
    owner: AccountWithMetadata,
    holder_ata: AccountWithMetadata,
    token_definition: AccountWithMetadata,
    ata_program_id: ProgramId,
    amount: u128,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    let token_program_id: lee_core::program::ProgramId = holder_ata.account.program_owner.into();
    assert!(owner.is_authorized, "Owner authorization is missing");
    let definition_id = TokenHolding::try_from(&holder_ata.account.data)
        .expect("Holder ATA must hold a valid token")
        .definition_id();
    let seed = associated_token_account_core::verify_ata_and_get_seed(
        &holder_ata,
        &owner,
        definition_id,
        ata_program_id,
    );

    let post_states = vec![
        AccountPostState::new(owner.account.clone()),
        AccountPostState::new(holder_ata.account.clone()),
        AccountPostState::new(token_definition.account.clone()),
    ];
    let mut holder_ata_auth = holder_ata.clone();
    holder_ata_auth.is_authorized = true;

    let chained_call = ChainedCall::new(
        token_program_id.into(),
        vec![token_definition.clone(), holder_ata_auth],
        &token_core::Instruction::Burn {
            amount_to_burn: amount,
        },
    )
    .with_pda_seeds(vec![seed]);
    (post_states, vec![chained_call])
}
