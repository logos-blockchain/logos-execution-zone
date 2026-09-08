use lee_core::{
    account::{AccountId, AccountInput, ProgramShardSelector},
    program::{AccountStateDiff, ChainedCall},
};

pub fn create_associated_token_account(
    owner: AccountInput,
    token_definition: AccountInput,
    ata_account: AccountInput,
    self_account_id: AccountId,
    token_program_id: AccountId,
) -> (Vec<AccountStateDiff>, Vec<ChainedCall>) {
    // No authorization check needed: create is idempotent, so anyone can call it safely.
    let ata_seed = associated_token_account_core::verify_ata_and_get_seed(
        &ata_account,
        &owner,
        token_definition.account_id,
        self_account_id,
        token_program_id,
    );

    let chained_calls = if ata_account.shard_of(token_program_id).is_empty() {
        vec![
            ChainedCall::new(
                token_program_id,
                vec![
                    ProgramShardSelector::from(&token_definition),
                    ProgramShardSelector::from(&ata_account),
                ],
                &token_core::Instruction::InitializeAccount,
            )
            .with_pda_seeds(vec![ata_seed]),
        ]
    } else {
        vec![]
    };

    let post_diffs = vec![
        AccountStateDiff::unchanged(owner),
        AccountStateDiff::unchanged(token_definition),
        AccountStateDiff::unchanged(ata_account),
    ];

    (post_diffs, chained_calls)
}
