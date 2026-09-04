use lee_core::{
    account::{AccountId, AccountWithMetadata},
    program::{AccountStateDiff, ChainedCall},
};

pub fn create_associated_token_account(
    owner: AccountWithMetadata,
    token_definition: AccountWithMetadata,
    ata_account: AccountWithMetadata,
    ata_program_id: AccountId,
) -> (Vec<AccountStateDiff>, Vec<ChainedCall>) {
    // No authorization check needed: create is idempotent, so anyone can call it safely.
    let token_program_id: AccountId = token_definition.account.program_owner;
    let ata_seed = associated_token_account_core::verify_ata_and_get_seed(
        &ata_account,
        &owner,
        token_definition.account_id,
        ata_program_id,
    );

    let post_diffs = vec![
        AccountStateDiff::unchanged(owner),
        AccountStateDiff::unchanged(token_definition.clone()),
        AccountStateDiff::unchanged(ata_account.clone()),
    ];

    // Idempotent: already initialized → no-op
    // TODO(squatting): the ATA address is derivable from (owner, mint) alone, so a
    // program that writes data there first owns it and turns this into a silent
    // no-op for ever. Accepted: there is no reclaim path today.
    if !ata_account.account.data.is_empty() {
        return (post_diffs, vec![]);
    }
    let chained_call = ChainedCall::new(
        token_program_id,
        vec![token_definition.account_id, ata_account.account_id],
        &token_core::Instruction::InitializeAccount,
    )
    .with_pda_seeds(vec![ata_seed]);

    (post_diffs, vec![chained_call])
}
