use lee_core::{
    account::{Input, Slot},
    program::{ChainedCall, ProgramId},
};
use token_core::TokenHolding;

#[must_use]
#[expect(
    clippy::needless_pass_by_value,
    reason = "consistent with codebase style"
)]
pub fn burn_from_associated_token_account(
    owner: Input,
    holder_ata: Input,
    token_definition: Input,
    ata_program_id: ProgramId,
    token_program_id: ProgramId,
    amount: u128,
) -> (Vec<Option<Slot>>, Vec<ChainedCall>) {
    assert!(owner.is_authorized, "Owner authorization is missing");
    let definition_id = TokenHolding::try_from(holder_ata.data(token_program_id))
        .expect("Holder ATA must hold a valid token")
        .definition_id();
    let seed = associated_token_account_core::verify_ata_and_get_seed(
        &holder_ata,
        &owner,
        definition_id,
        ata_program_id,
    );

    let post_states = vec![
        owner.unchanged(),
        holder_ata.unchanged(),
        token_definition.unchanged(),
    ];

    let mut holder_ata_auth = holder_ata;
    holder_ata_auth.is_authorized = true;

    let chained_call = ChainedCall::new(
        token_program_id,
        vec![token_definition, holder_ata_auth],
        &token_core::Instruction::Burn {
            amount_to_burn: amount,
        },
    )
    .with_pda_seeds(vec![seed]);

    (post_states, vec![chained_call])
}
