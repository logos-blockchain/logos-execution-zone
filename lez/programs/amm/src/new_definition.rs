use std::num::NonZero;

use amm_core::{PoolDefinition, compute_liquidity_token_pda, compute_pool_pda, compute_vault_pda};
use lee_core::{account::AccountId, program::ReceiveInput};

#[must_use]
pub fn new_pool(
    input: &ReceiveInput,
    token_a_amount: u128,
    token_b_amount: u128,
    token_program_id: AccountId,
    definition_token_a_id: AccountId,
    definition_token_b_id: AccountId,
) -> (PoolDefinition, bool) {
    let token_a_amount =
        NonZero::new(token_a_amount).expect("Token A should have a nonzero amount");
    let token_b_amount =
        NonZero::new(token_b_amount).expect("Token B should have a nonzero amount");
    assert!(
        definition_token_a_id != definition_token_b_id,
        "Cannot set up a swap for a token with itself"
    );
    let amm_program_id = input.receiver.program_account_id;
    let pool_id = input.receiver.account_id;
    assert_eq!(
        pool_id,
        compute_pool_pda(
            amm_program_id,
            definition_token_a_id,
            definition_token_b_id,
            token_program_id
        ),
        "Pool Definition Account ID does not match PDA"
    );

    let pool_was_empty = input.pre_data.is_empty();
    if !pool_was_empty {
        let existing = PoolDefinition::try_from(&input.pre_data)
            .expect("AMM program expects a valid Pool account");
        assert!(
            !existing.active,
            "Cannot initialize an active Pool Definition"
        );
    }

    let initial_lp = token_a_amount
        .get()
        .checked_mul(token_b_amount.get())
        .expect("token A amount * token B amount overflows u128")
        .isqrt();

    (
        PoolDefinition {
            token_program_id,
            definition_token_a_id,
            definition_token_b_id,
            vault_a_id: compute_vault_pda(amm_program_id, pool_id, definition_token_a_id),
            vault_b_id: compute_vault_pda(amm_program_id, pool_id, definition_token_b_id),
            liquidity_pool_id: compute_liquidity_token_pda(amm_program_id, pool_id),
            liquidity_pool_supply: initial_lp,
            reserve_a: token_a_amount.get(),
            reserve_b: token_b_amount.get(),
            fees: 0_u128, // TODO: we assume all fees are 0 for now.
            active: true,
        },
        pool_was_empty,
    )
}
