use lee_core::{
    account::{Account, AccountId, AccountWithMetadata},
    program::{AccountPostState, ChainedCall, Claim},
};

pub fn create_associated_token_account(
    owner: AccountWithMetadata,
    token_definition: AccountWithMetadata,
    ata_account: AccountWithMetadata,
    ata_account_id: AccountId,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    // No authorization check needed: create is idempotent, so anyone can call it safely.
    let token_account_id = token_definition.account.program_owner;
    let ata_seed = associated_token_account_core::verify_ata_and_get_seed(
        &ata_account,
        &owner,
        token_definition.account_id,
        ata_account_id,
    );

    // Idempotent: already initialized → no-op
    if ata_account.account != Account::default() {
        return (
            vec![
                AccountPostState::new_claimed_if_default(owner.account.clone(), Claim::Authorized),
                AccountPostState::new(token_definition.account.clone()),
                AccountPostState::new(ata_account.account.clone()),
            ],
            vec![],
        );
    }

    let post_states = vec![
        AccountPostState::new_claimed_if_default(owner.account.clone(), Claim::Authorized),
        AccountPostState::new(token_definition.account.clone()),
        AccountPostState::new(ata_account.account.clone()),
    ];
    let ata_account_auth = AccountWithMetadata {
        is_authorized: true,
        ..ata_account.clone()
    };
    let chained_call = ChainedCall::new(
        token_account_id,
        vec![token_definition.clone(), ata_account_auth],
        &token_core::Instruction::InitializeAccount,
    )
    .with_pda_seeds(vec![ata_seed]);

    (post_states, vec![chained_call])
}
