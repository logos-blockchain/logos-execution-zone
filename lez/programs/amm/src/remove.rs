use std::num::NonZeroU128;

use amm_core::PoolDefinition;
use lee_core::{
    account::{AccountId, BalanceDiff, ProgramShardSelector, ShardData},
    program::{AccountInput, AccountStateDiff, ChainedCall},
};
use token_core::HoldingTarget;

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
#[must_use]
pub fn remove_liquidity(
    pool: &AccountInput,
    vault_a: &AccountInput,
    vault_b: &AccountInput,
    pool_definition_lp: &AccountInput,
    user_holding_a: &AccountInput,
    user_holding_b: &AccountInput,
    user_holding_lp: &AccountInput,
    user_owner: &AccountInput,
    remove_liquidity_amount: NonZeroU128,
    min_amount_to_remove_token_a: u128,
    min_amount_to_remove_token_b: u128,
    self_account_id: AccountId,
    user: &HoldingTarget,
) -> (Vec<AccountStateDiff>, Vec<ChainedCall>) {
    let remove_liquidity_amount: u128 = remove_liquidity_amount.into();

    // 1. Fetch Pool state
    let pool_def_data = PoolDefinition::try_from(pool.shard_of(self_account_id))
        .expect("Remove liquidity: AMM Program expects a valid Pool Definition Account");
    let token_program_id = pool_def_data.token_program_id;
    let pool_seed = crate::pool_seed(pool, &pool_def_data, self_account_id);

    assert!(pool_def_data.active, "Pool is inactive");
    assert_eq!(
        pool_def_data.liquidity_pool_id, pool_definition_lp.account_id,
        "LP definition mismatch"
    );
    assert_eq!(
        vault_a.account_id, pool_def_data.vault_a_id,
        "Vault A was not provided"
    );
    assert_eq!(
        vault_b.account_id, pool_def_data.vault_b_id,
        "Vault B was not provided"
    );
    assert_eq!(
        user_owner.account_id, user.owner_id,
        "User owner was not provided"
    );

    assert!(
        min_amount_to_remove_token_a != 0,
        "Minimum withdraw amount must be nonzero"
    );
    assert!(
        min_amount_to_remove_token_b != 0,
        "Minimum withdraw amount must be nonzero"
    );

    // 2. Compute withdrawal amounts
    let user_holding_lp_data = token_core::TokenHolding::try_from(
        user_holding_lp.shard_of(token_program_id),
    )
    .expect("Remove liquidity: AMM Program expects a valid Token Account for liquidity token");
    let token_core::TokenHolding::Fungible {
        definition_id: _,
        balance: user_lp_balance,
    } = user_holding_lp_data
    else {
        panic!(
            "Remove liquidity: AMM Program expects a valid Fungible Token Holding Account for liquidity token"
        );
    };

    assert!(
        user_lp_balance <= pool_def_data.liquidity_pool_supply,
        "Invalid liquidity account provided"
    );
    assert_eq!(
        user_holding_lp_data.definition_id(),
        pool_def_data.liquidity_pool_id,
        "Invalid liquidity account provided"
    );

    let withdraw_amount_a =
        (pool_def_data.reserve_a * remove_liquidity_amount) / pool_def_data.liquidity_pool_supply;
    let withdraw_amount_b =
        (pool_def_data.reserve_b * remove_liquidity_amount) / pool_def_data.liquidity_pool_supply;

    // 3. Validate and slippage check
    assert!(
        withdraw_amount_a >= min_amount_to_remove_token_a,
        "Insufficient minimal withdraw amount (Token A) provided for liquidity amount"
    );
    assert!(
        withdraw_amount_b >= min_amount_to_remove_token_b,
        "Insufficient minimal withdraw amount (Token B) provided for liquidity amount"
    );

    // 4. Calculate LP to reduce cap by
    let delta_lp: u128 = (pool_def_data.liquidity_pool_supply * remove_liquidity_amount)
        / pool_def_data.liquidity_pool_supply;

    let active: bool = pool_def_data.liquidity_pool_supply - delta_lp != 0;

    // 5. Update pool account
    let pool_post_definition = PoolDefinition {
        liquidity_pool_supply: pool_def_data.liquidity_pool_supply - delta_lp,
        reserve_a: pool_def_data.reserve_a - withdraw_amount_a,
        reserve_b: pool_def_data.reserve_b - withdraw_amount_b,
        active,
        ..pool_def_data
    };

    // Chaincall for Token A withdraw
    let call_token_a = crate::withdraw(
        token_program_id,
        vault_a,
        user_holding_a,
        user,
        pool.account_id,
        pool_seed,
        withdraw_amount_a,
    );
    // Chaincall for Token B withdraw
    let call_token_b = crate::withdraw(
        token_program_id,
        vault_b,
        user_holding_b,
        user,
        pool.account_id,
        pool_seed,
        withdraw_amount_b,
    );
    // Chaincall for LP adjustment
    let call_token_lp = ChainedCall::new(
        token_program_id,
        vec![
            ProgramShardSelector::from(pool_definition_lp),
            ProgramShardSelector::from(user_holding_lp),
            ProgramShardSelector::balance(user.owner_id),
        ],
        &token_core::Instruction::Burn {
            holder: user.clone(),
            amount_to_burn: delta_lp,
        },
    );

    let chained_calls = vec![call_token_lp, call_token_b, call_token_a];

    let post_diffs = vec![
        AccountStateDiff::new(
            pool.clone(),
            BalanceDiff::Add(0),
            ShardData::from(&pool_post_definition),
        ),
        AccountStateDiff::unchanged(vault_a.clone()),
        AccountStateDiff::unchanged(vault_b.clone()),
        AccountStateDiff::unchanged(pool_definition_lp.clone()),
        AccountStateDiff::unchanged(user_holding_a.clone()),
        AccountStateDiff::unchanged(user_holding_b.clone()),
        AccountStateDiff::unchanged(user_holding_lp.clone()),
        AccountStateDiff::unchanged(user_owner.clone()),
    ];

    (post_diffs, chained_calls)
}
