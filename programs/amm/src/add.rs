use std::num::NonZeroU128;

use amm_core::{PoolDefinition, compute_liquidity_token_pda_seed};
use nssa_core::{
    account::{AccountWithMetadata, Data},
    program::{AccountPostState, ChainedCall},
};

use crate::vault_utils::read_vault_fungible_balances;

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
pub fn add_liquidity(
    pool: AccountWithMetadata,
    vault_a: AccountWithMetadata,
    vault_b: AccountWithMetadata,
    pool_definition_lp: AccountWithMetadata,
    user_holding_a: AccountWithMetadata,
    user_holding_b: AccountWithMetadata,
    user_holding_lp: AccountWithMetadata,
    min_amount_liquidity: NonZeroU128,
    max_amount_to_add_token_a: u128,
    max_amount_to_add_token_b: u128,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    // 1. Fetch Pool state
    let pool_def_data = PoolDefinition::try_from(&pool.account.data)
        .expect("Add liquidity: AMM Program expects valid Pool Definition Account");

    assert_eq!(
        vault_a.account_id, pool_def_data.vault_a_id,
        "Vault A was not provided"
    );

    assert_eq!(
        pool_def_data.liquidity_pool_id, pool_definition_lp.account_id,
        "LP definition mismatch"
    );

    assert_eq!(
        vault_b.account_id, pool_def_data.vault_b_id,
        "Vault B was not provided"
    );

    assert!(
        max_amount_to_add_token_a != 0 && max_amount_to_add_token_b != 0,
        "Both max-balances must be nonzero"
    );

    // 2. Determine deposit amount
    let (vault_a_balance, vault_b_balance) = read_vault_fungible_balances(&vault_a, &vault_b);

    assert!(pool_def_data.reserve_a != 0, "Reserves must be nonzero");
    assert!(pool_def_data.reserve_b != 0, "Reserves must be nonzero");
    assert!(
        vault_a_balance >= pool_def_data.reserve_a,
        "Vaults' balances must be at least the reserve amounts"
    );
    assert!(
        vault_b_balance >= pool_def_data.reserve_b,
        "Vaults' balances must be at least the reserve amounts"
    );

    // Calculate actual_amounts
    let ideal_a: u128 =
        (pool_def_data.reserve_a * max_amount_to_add_token_b) / pool_def_data.reserve_b;
    let ideal_b: u128 =
        (pool_def_data.reserve_b * max_amount_to_add_token_a) / pool_def_data.reserve_a;

    let actual_amount_a = if ideal_a > max_amount_to_add_token_a {
        max_amount_to_add_token_a
    } else {
        ideal_a
    };
    let actual_amount_b = if ideal_b > max_amount_to_add_token_b {
        max_amount_to_add_token_b
    } else {
        ideal_b
    };

    // 3. Validate amounts
    assert!(
        max_amount_to_add_token_a >= actual_amount_a,
        "Actual trade amounts cannot exceed max_amounts"
    );
    assert!(
        max_amount_to_add_token_b >= actual_amount_b,
        "Actual trade amounts cannot exceed max_amounts"
    );

    assert!(actual_amount_a != 0, "A trade amount is 0");
    assert!(actual_amount_b != 0, "A trade amount is 0");

    // 4. Calculate LP to mint
    let delta_lp = std::cmp::min(
        pool_def_data.liquidity_pool_supply * actual_amount_a / pool_def_data.reserve_a,
        pool_def_data.liquidity_pool_supply * actual_amount_b / pool_def_data.reserve_b,
    );

    assert!(delta_lp != 0, "Payable LP must be nonzero");

    assert!(
        delta_lp >= min_amount_liquidity.get(),
        "Payable LP is less than provided minimum LP amount"
    );

    // 5. Update pool account
    let mut pool_post = pool.account.clone();
    let pool_post_definition = PoolDefinition {
        liquidity_pool_supply: pool_def_data.liquidity_pool_supply + delta_lp,
        reserve_a: pool_def_data.reserve_a + actual_amount_a,
        reserve_b: pool_def_data.reserve_b + actual_amount_b,
        ..pool_def_data
    };

    pool_post.data = Data::from(&pool_post_definition);
    let token_program_id = user_holding_a.account.program_owner;

    // Chain call for Token A (UserHoldingA -> Vault_A)
    let call_token_a = ChainedCall::new(
        token_program_id,
        vec![user_holding_a.clone(), vault_a.clone()],
        &token_core::Instruction::Transfer {
            amount_to_transfer: actual_amount_a,
        },
    );
    // Chain call for Token B (UserHoldingB -> Vault_B)
    let call_token_b = ChainedCall::new(
        token_program_id,
        vec![user_holding_b.clone(), vault_b.clone()],
        &token_core::Instruction::Transfer {
            amount_to_transfer: actual_amount_b,
        },
    );
    // Chain call for LP (mint new tokens for user_holding_lp)
    let mut pool_definition_lp_auth = pool_definition_lp.clone();
    pool_definition_lp_auth.is_authorized = true;
    let call_token_lp = ChainedCall::new(
        token_program_id,
        vec![pool_definition_lp_auth.clone(), user_holding_lp.clone()],
        &token_core::Instruction::Mint {
            amount_to_mint: delta_lp,
        },
    )
    .with_pda_seeds(vec![compute_liquidity_token_pda_seed(pool.account_id)]);

    let chained_calls = vec![call_token_lp, call_token_b, call_token_a];

    let post_states = vec![
        AccountPostState::new(pool_post),
        AccountPostState::new(vault_a.account.clone()),
        AccountPostState::new(vault_b.account.clone()),
        AccountPostState::new(pool_definition_lp.account.clone()),
        AccountPostState::new(user_holding_a.account.clone()),
        AccountPostState::new(user_holding_b.account.clone()),
        AccountPostState::new(user_holding_lp.account.clone()),
    ];

    (post_states, chained_calls)
}
