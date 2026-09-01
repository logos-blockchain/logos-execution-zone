use lee_core::{
    account::{Account, AccountWithMetadata},
    program::{ChainedCall, ProgramId},
};

pub fn create_associated_token_account(
    owner: AccountWithMetadata,
    token_definition: AccountWithMetadata,
    ata_account: AccountWithMetadata,
    ata_program_id: ProgramId,
) -> (Vec<Account>, Vec<ChainedCall>) {
    // No authorization check needed: create is idempotent, so anyone can call it safely.
    let token_program_id: lee_core::program::ProgramId =
        token_definition.account.program_owner.into();
    let ata_seed = associated_token_account_core::verify_ata_and_get_seed(
        &ata_account,
        &owner,
        token_definition.account_id,
        ata_program_id,
    );

    // Idempotent: already initialized → no-op
    // TODO(squatting): the ATA address is derivable from (owner, mint) alone, so a
    // program that writes data there first owns it and turns this into a silent
    // no-op for ever. Accepted: there is no reclaim path today.
    if !ata_account.account.data.is_empty() {
        return (
            vec![
                owner.account.clone(),
                token_definition.account.clone(),
                ata_account.account.clone(),
            ],
            vec![],
        );
    }

    let post_states = vec![
        owner.account.clone(),
        token_definition.account.clone(),
        ata_account.account.clone(),
    ];
    let ata_account_auth = AccountWithMetadata {
        is_authorized: true,
        ..ata_account.clone()
    };
    let chained_call = ChainedCall::new(
        token_program_id,
        vec![token_definition.clone(), ata_account_auth],
        &token_core::Instruction::InitializeAccount,
    )
    .with_pda_seeds(vec![ata_seed]);

    (post_states, vec![chained_call])
}
