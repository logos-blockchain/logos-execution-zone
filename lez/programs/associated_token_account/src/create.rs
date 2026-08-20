use lee_core::{
    account::{Account, AccountDiff, AccountWithMetadata, BalanceDiff},
    program::{AccountDiffOutput, ChainedCall, Claim, ProgramId},
};

pub fn create_associated_token_account(
    owner: AccountWithMetadata,
    token_definition: AccountWithMetadata,
    ata_account: AccountWithMetadata,
    ata_program_id: ProgramId,
) -> (Vec<AccountDiffOutput>, Vec<ChainedCall>) {
    // No authorization check needed: create is idempotent, so anyone can call it safely.
    let token_program_id: lee_core::program::ProgramId =
        token_definition.account.program_owner.into();
    let ata_seed = associated_token_account_core::verify_ata_and_get_seed(
        &ata_account,
        &owner,
        token_definition.account_id,
        ata_program_id,
    );

    let owner_post = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: owner.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: None,
        },
        owner.account.program_owner.into(),
        Claim::Authorized,
    );

    // Idempotent: already initialized → no-op
    if ata_account.account != Account::default() {
        return (
            vec![
                owner_post,
                crate::unchanged(token_definition.account_id),
                crate::unchanged(ata_account.account_id),
            ],
            vec![],
        );
    }

    let post_states = vec![
        owner_post,
        crate::unchanged(token_definition.account_id),
        crate::unchanged(ata_account.account_id),
    ];
    let chained_call = ChainedCall::new(
        token_program_id,
        vec![token_definition.account_id, ata_account.account_id],
        &token_core::Instruction::InitializeAccount,
    )
    .with_pda_seeds(vec![ata_seed]);

    (post_states, vec![chained_call])
}
