use lee_core::{
    account::{Account, AccountWithMetadata},
    program::{ChainedCall, ProgramId},
};

pub fn create_associated_token_account(
    owner: AccountWithMetadata,
    token_definition: AccountWithMetadata,
    ata_account: AccountWithMetadata,
    ata_program_id: ProgramId,
    token_program_id: ProgramId,
) -> (Vec<Account>, Vec<ChainedCall>) {
    // No authorization check needed: create is idempotent, so anyone can call it safely.
    associated_token_account_core::verify_ata_and_get_seed(
        &ata_account,
        &owner,
        token_definition.account_id,
        ata_program_id,
    );

    let post_states = vec![
        owner.account.clone(),
        token_definition.account.clone(),
        ata_account.account.clone(),
    ];

    // Idempotent: already initialized → no-op
    if !ata_account.account.data(token_program_id).is_empty() {
        return (post_states, vec![]);
    }

    let chained_call = ChainedCall::new(
        token_program_id,
        vec![token_definition, ata_account],
        &token_core::Instruction::InitializeAccount,
    );

    (post_states, vec![chained_call])
}
