use lee_core::{
    account::{Input, Slot},
    program::{ChainedCall, ProgramId},
};

pub fn close_associated_token_account(
    owner: Input,
    ata_account: Input,
    token_definition: Input,
    ata_program_id: ProgramId,
    token_program_id: ProgramId,
) -> (Vec<Option<Slot>>, Vec<ChainedCall>) {
    assert!(owner.is_authorized, "Owner authorization is missing");

    // Derived from the definition the caller names, never from the holding's own:
    // the point is to clear an address whose holding names the wrong definition.
    let seed = associated_token_account_core::verify_ata_and_get_seed(
        &ata_account,
        &owner,
        token_definition.account_id,
        ata_program_id,
    );

    let post_states = vec![
        owner.unchanged(),
        ata_account.unchanged(),
        token_definition.unchanged(),
    ];

    let mut ata_authorized = ata_account;
    ata_authorized.is_authorized = true;

    let chained_call = ChainedCall::new(
        token_program_id,
        vec![ata_authorized],
        &token_core::Instruction::CloseHolding,
    )
    .with_pda_seeds(vec![seed]);

    (post_states, vec![chained_call])
}
