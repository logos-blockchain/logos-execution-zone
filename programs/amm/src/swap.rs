pub use amm_core::{PoolDefinition, compute_liquidity_token_pda_seed, compute_vault_pda_seed};
use nssa_core::{
    account::{AccountId, AccountWithMetadata, Data},
    program::{AccountPostState, ChainedCall},
};

use crate::vault_utils::read_vault_fungible_balances;

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
#[must_use]
pub fn swap(
    pool: AccountWithMetadata,
    vault_a: AccountWithMetadata,
    vault_b: AccountWithMetadata,
    user_holding_a: AccountWithMetadata,
    user_holding_b: AccountWithMetadata,
    swap_amount_in: u128,
    min_amount_out: u128,
    token_in_id: AccountId,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    assert!(swap_amount_in > 0, "Swap amount in should be nonzero");

    // Verify vaults are in fact vaults
    let pool_def_data = PoolDefinition::try_from(&pool.account.data)
        .expect("Swap: AMM Program expects a valid Pool Definition Account");

    assert!(pool_def_data.active, "Pool is inactive");
    assert_eq!(
        vault_a.account_id, pool_def_data.vault_a_id,
        "Vault A was not provided"
    );
    assert_eq!(
        vault_b.account_id, pool_def_data.vault_b_id,
        "Vault B was not provided"
    );
    assert!(pool_def_data.reserve_a != 0, "Reserves must be nonzero");
    assert!(pool_def_data.reserve_b != 0, "Reserves must be nonzero");

    // fetch pool reserves
    // validates reserves is at least the vaults' balances
    let (vault_a_balance, vault_b_balance) =
        read_vault_fungible_balances("Swap", &vault_a, &vault_b);

    assert!(
        vault_a_balance >= pool_def_data.reserve_a,
        "Reserve for Token A exceeds vault balance"
    );

    assert!(
        vault_b_balance >= pool_def_data.reserve_b,
        "Reserve for Token B exceeds vault balance"
    );

    let (chained_calls, [deposit_a, withdraw_a], [deposit_b, withdraw_b]) =
        if token_in_id == pool_def_data.definition_token_a_id {
            let (chained_calls, deposit_a, withdraw_b) = swap_logic(
                user_holding_a.clone(),
                vault_a.clone(),
                vault_b.clone(),
                user_holding_b.clone(),
                swap_amount_in,
                min_amount_out,
                pool_def_data.reserve_a,
                pool_def_data.reserve_b,
                pool.account_id,
            );

            (chained_calls, [deposit_a, 0], [0, withdraw_b])
        } else if token_in_id == pool_def_data.definition_token_b_id {
            let (chained_calls, deposit_b, withdraw_a) = swap_logic(
                user_holding_b.clone(),
                vault_b.clone(),
                vault_a.clone(),
                user_holding_a.clone(),
                swap_amount_in,
                min_amount_out,
                pool_def_data.reserve_b,
                pool_def_data.reserve_a,
                pool.account_id,
            );

            (chained_calls, [0, withdraw_a], [deposit_b, 0])
        } else {
            panic!("AccountId is not a token type for the pool");
        };

    let old_reserve_a = pool_def_data.reserve_a;
    let old_reserve_b = pool_def_data.reserve_b;

    let new_reserve_a = old_reserve_a
        .checked_add(deposit_a)
        .expect("Reserve A overflow on swap deposit")
        .checked_sub(withdraw_a)
        .expect("Reserve A underflow on swap withdrawal");
    let new_reserve_b = old_reserve_b
        .checked_add(deposit_b)
        .expect("Reserve B overflow on swap deposit")
        .checked_sub(withdraw_b)
        .expect("Reserve B underflow on swap withdrawal");

    let old_k = mul_u128_wide(old_reserve_a, old_reserve_b);
    let new_k = mul_u128_wide(new_reserve_a, new_reserve_b);

    assert!(
        new_k >= old_k,
        "Swap invariant violation: new k must be greater than or equal to old k"
    );

    // Update pool account
    let mut pool_post = pool.account;
    let pool_post_definition = PoolDefinition {
        reserve_a: new_reserve_a,
        reserve_b: new_reserve_b,
        ..pool_def_data
    };

    pool_post.data = Data::from(&pool_post_definition);

    let post_states = vec![
        AccountPostState::new(pool_post),
        AccountPostState::new(vault_a.account),
        AccountPostState::new(vault_b.account),
        AccountPostState::new(user_holding_a.account),
        AccountPostState::new(user_holding_b.account),
    ];

    (post_states, chained_calls)
}

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
fn swap_logic(
    user_deposit: AccountWithMetadata,
    vault_deposit: AccountWithMetadata,
    vault_withdraw: AccountWithMetadata,
    user_withdraw: AccountWithMetadata,
    swap_amount_in: u128,
    min_amount_out: u128,
    reserve_deposit_vault_amount: u128,
    reserve_withdraw_vault_amount: u128,
    pool_id: AccountId,
) -> (Vec<ChainedCall>, u128, u128) {
    // Compute withdraw amount
    // Maintains pool constant product
    // k = pool_def_data.reserve_a * pool_def_data.reserve_b;
    let withdraw_numerator = reserve_withdraw_vault_amount
        .checked_mul(swap_amount_in)
        .expect("Swap withdraw numerator overflow");
    let withdraw_denominator = reserve_deposit_vault_amount
        .checked_add(swap_amount_in)
        .expect("Swap withdraw denominator overflow");
    let withdraw_amount = withdraw_numerator / withdraw_denominator;

    // Slippage check
    assert!(
        min_amount_out <= withdraw_amount,
        "Withdraw amount is less than minimal amount out"
    );
    assert!(withdraw_amount != 0, "Withdraw amount should be nonzero");

    let token_program_id = user_deposit.account.program_owner;

    let mut chained_calls = Vec::new();
    chained_calls.push(ChainedCall::new(
        token_program_id,
        vec![user_deposit, vault_deposit],
        &token_core::Instruction::Transfer {
            amount_to_transfer: swap_amount_in,
        },
    ));

    let mut vault_withdraw = vault_withdraw;
    vault_withdraw.is_authorized = true;

    let pda_seed = compute_vault_pda_seed(
        pool_id,
        token_core::TokenHolding::try_from(&vault_withdraw.account.data)
            .expect("Swap Logic: AMM Program expects valid token data")
            .definition_id(),
    );

    chained_calls.push(
        ChainedCall::new(
            token_program_id,
            vec![vault_withdraw, user_withdraw],
            &token_core::Instruction::Transfer {
                amount_to_transfer: withdraw_amount,
            },
        )
        .with_pda_seeds(vec![pda_seed]),
    );

    (chained_calls, swap_amount_in, withdraw_amount)
}

fn mul_u128_wide(a: u128, b: u128) -> (u128, u128) {
    let (lo, hi) = a.carrying_mul(b, 0);
    (hi, lo)
}
