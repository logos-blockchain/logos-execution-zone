use lee_core::{
    account::{AccountId, Input, Position},
    program::{ChainedCall, ShardStateDiff},
};

pub fn create_associated_token_account(
    owner: Input,
    token_definition: Input,
    ata_account: Input,
    self_account_id: AccountId,
    token_program_id: AccountId,
) -> (Vec<ShardStateDiff>, Vec<ChainedCall>) {
    // No authorization check needed: create is idempotent, so anyone can call it safely.
    let ata_seed = associated_token_account_core::verify_ata_and_get_seed(
        &ata_account,
        &owner,
        token_definition.account_id,
        self_account_id,
        token_program_id,
    );

    // Idempotent: an ATA the token program already wrote needs no initialization.
    let chained_calls = if ata_account.shard_of(token_program_id).is_empty() {
        vec![
            ChainedCall::new(
                token_program_id,
                vec![
                    Position::from(&token_definition),
                    Position::from(&ata_account),
                ],
                &token_core::Instruction::InitializeAccount,
            )
            .with_pda_seeds(vec![ata_seed]),
        ]
    } else {
        vec![]
    };

    let post_diffs = vec![
        ShardStateDiff::unchanged(owner),
        ShardStateDiff::unchanged(token_definition),
        ShardStateDiff::unchanged(ata_account),
    ];

    (post_diffs, chained_calls)
}
