use lee_core::{
    account::{Account, AccountWithMetadata, BalanceDiff},
    program::{AccountStateDiff, ChainedCall, Claim, ProgramId},
};

pub fn create_associated_token_account(
    owner: AccountWithMetadata,
    token_definition: AccountWithMetadata,
    ata_account: AccountWithMetadata,
    ata_program_id: ProgramId,
) -> (Vec<AccountStateDiff>, Vec<ChainedCall>) {
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
    if ata_account.account != Account::default() {
        return (
            vec![
                AccountStateDiff::new_claimed_if_default(
                    owner.clone(),
                    BalanceDiff::Add(0),
                    owner.account.data.clone(),
                    Claim::Authorized,
                ),
                AccountStateDiff::unchanged(token_definition.clone()),
                AccountStateDiff::unchanged(ata_account.clone()),
            ],
            vec![],
        );
    }

    let post_diffs = vec![
        AccountStateDiff::new_claimed_if_default(
            owner.clone(),
            BalanceDiff::Add(0),
            owner.account.data.clone(),
            Claim::Authorized,
        ),
        AccountStateDiff::unchanged(token_definition.clone()),
        AccountStateDiff::unchanged(ata_account.clone()),
    ];
    let chained_call = ChainedCall::new(
        token_program_id,
        vec![token_definition.account_id, ata_account.account_id],
        &token_core::Instruction::InitializeAccount,
    )
    .with_pda_seeds(vec![ata_seed]);

    (post_diffs, vec![chained_call])
}
