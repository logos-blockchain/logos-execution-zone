use lee_core::{
    account::{AccountId, Input, Position},
    program::{ChainedCall, ShardStateDiff},
};
use token_core::TokenHolding;

pub fn transfer_from_associated_token_account(
    owner: Input,
    sender_ata: Input,
    recipient: Input,
    self_account_id: AccountId,
    token_program_id: AccountId,
    amount: u128,
) -> (Vec<ShardStateDiff>, Vec<ChainedCall>) {
    assert!(owner.is_authorized, "Owner authorization is missing");
    let definition_id = TokenHolding::try_from(sender_ata.shard_of(token_program_id))
        .expect("Sender ATA must hold a valid token")
        .definition_id();
    let seed = associated_token_account_core::verify_ata_and_get_seed(
        &sender_ata,
        &owner,
        definition_id,
        self_account_id,
    );

    let transfer_positions = vec![Position::from(&sender_ata), Position::from(&recipient)];
    let post_diffs = vec![
        ShardStateDiff::unchanged(owner),
        ShardStateDiff::unchanged(sender_ata),
        ShardStateDiff::unchanged(recipient),
    ];
    let chained_call = ChainedCall::new(
        token_program_id,
        transfer_positions,
        &token_core::Instruction::Transfer {
            amount_to_transfer: amount,
        },
    )
    .with_pda_seeds(vec![seed]);
    (post_diffs, vec![chained_call])
}
