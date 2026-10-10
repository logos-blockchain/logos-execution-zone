use amm_core::PoolDefinition;

#[must_use]
pub fn pool_after_remove(
    pool: &PoolDefinition,
    remove_liquidity_amount: u128,
    amount_to_remove_token_a: u128,
    amount_to_remove_token_b: u128,
) -> PoolDefinition {
    assert!(
        remove_liquidity_amount != 0,
        "Remove liquidity amount must be nonzero"
    );
    assert!(
        amount_to_remove_token_a != 0 && amount_to_remove_token_b != 0,
        "Withdraw amounts must be nonzero"
    );

    assert!(pool.active, "Pool is inactive");
    // The recorded supply rises only when this program mints the same LP and falls only when it
    // burns the same LP here; a holder burning LP directly only lowers what is outstanding.
    let liquidity_pool_supply = pool
        .liquidity_pool_supply
        .checked_sub(remove_liquidity_amount)
        .expect("Removal burns more LP than the pool's supply");

    let withdraw_amount_a = amm_core::withdrawal_share(
        pool.reserve_a,
        remove_liquidity_amount,
        pool.liquidity_pool_supply,
    )
    .expect("reserve * liquidity amount overflows u128");
    let withdraw_amount_b = amm_core::withdrawal_share(
        pool.reserve_b,
        remove_liquidity_amount,
        pool.liquidity_pool_supply,
    )
    .expect("reserve * liquidity amount overflows u128");

    assert_eq!(
        withdraw_amount_a, amount_to_remove_token_a,
        "Proposed Token A withdrawal does not match the pool's removal calculation"
    );
    assert_eq!(
        withdraw_amount_b, amount_to_remove_token_b,
        "Proposed Token B withdrawal does not match the pool's removal calculation"
    );

    PoolDefinition {
        liquidity_pool_supply,
        reserve_a: pool
            .reserve_a
            .checked_sub(withdraw_amount_a)
            .expect("a share never exceeds its reserve"),
        reserve_b: pool
            .reserve_b
            .checked_sub(withdraw_amount_b)
            .expect("a share never exceeds its reserve"),
        active: liquidity_pool_supply != 0,
        ..pool.clone()
    }
}
