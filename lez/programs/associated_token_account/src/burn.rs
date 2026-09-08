use lee_core::{
    account::{AccountId, AccountInput, ProgramShardSelector},
    program::{AccountStateDiff, ChainedCall},
};
use token_core::TokenHolding;

pub fn burn_from_associated_token_account(
    owner: AccountInput,
    holder_ata: AccountInput,
    token_definition: AccountInput,
    self_account_id: AccountId,
    token_program_id: AccountId,
    amount: u128,
) -> (Vec<AccountStateDiff>, Vec<ChainedCall>) {
    assert!(owner.is_authorized, "Owner authorization is missing");
    let definition_id = TokenHolding::try_from(holder_ata.shard_of(token_program_id))
        .expect("Holder ATA must hold a valid token")
        .definition_id();
    let seed = associated_token_account_core::verify_ata_and_get_seed(
        &holder_ata,
        &owner,
        definition_id,
        self_account_id,
        token_program_id,
    );

    let burn_shard_selectors = vec![
        ProgramShardSelector::from(&token_definition),
        ProgramShardSelector::from(&holder_ata),
    ];
    let post_diffs = vec![
        AccountStateDiff::unchanged(owner),
        AccountStateDiff::unchanged(holder_ata),
        AccountStateDiff::unchanged(token_definition),
    ];
    let chained_call = ChainedCall::new(
        token_program_id,
        burn_shard_selectors,
        &token_core::Instruction::Burn {
            amount_to_burn: amount,
        },
    )
    .with_pda_seeds(vec![seed]);
    (post_diffs, vec![chained_call])
}
