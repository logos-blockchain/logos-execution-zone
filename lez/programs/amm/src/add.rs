use amm_core::PoolDefinition;

#[must_use]
pub fn pool_after_add(
    pool: &PoolDefinition,
    max_amount_to_add_token_a: u128,
    max_amount_to_add_token_b: u128,
    amount_to_add_token_a: u128,
    amount_to_add_token_b: u128,
    amount_liquidity: u128,
) -> PoolDefinition {
    assert!(
        max_amount_to_add_token_a != 0 && max_amount_to_add_token_b != 0,
        "Both max-balances must be nonzero"
    );
    assert!(
        max_amount_to_add_token_a >= amount_to_add_token_a,
        "Actual trade amounts cannot exceed max_amounts"
    );
    assert!(
        max_amount_to_add_token_b >= amount_to_add_token_b,
        "Actual trade amounts cannot exceed max_amounts"
    );
    assert!(amount_to_add_token_a != 0, "A trade amount is 0");
    assert!(amount_to_add_token_b != 0, "A trade amount is 0");
    assert!(amount_liquidity != 0, "Payable LP must be nonzero");

    assert!(pool.reserve_a != 0, "Reserves must be nonzero");
    assert!(pool.reserve_b != 0, "Reserves must be nonzero");

    let ideal_a =
        amm_core::ideal_deposit(pool.reserve_a, pool.reserve_b, max_amount_to_add_token_b)
            .expect("reserve * max amount overflows u128");
    let ideal_b =
        amm_core::ideal_deposit(pool.reserve_b, pool.reserve_a, max_amount_to_add_token_a)
            .expect("reserve * max amount overflows u128");

    let actual_amount_a = ideal_a.min(max_amount_to_add_token_a);
    let actual_amount_b = ideal_b.min(max_amount_to_add_token_b);

    assert_eq!(
        actual_amount_a, amount_to_add_token_a,
        "Proposed Token A deposit does not match the pool's ideal amount"
    );
    assert_eq!(
        actual_amount_b, amount_to_add_token_b,
        "Proposed Token B deposit does not match the pool's ideal amount"
    );

    let delta_lp = amm_core::liquidity_minted(
        pool.liquidity_pool_supply,
        actual_amount_a,
        actual_amount_b,
        pool.reserve_a,
        pool.reserve_b,
    )
    .expect("supply * amount overflows u128");

    assert_eq!(
        delta_lp, amount_liquidity,
        "Proposed LP amount does not match the pool's mint calculation"
    );

    PoolDefinition {
        liquidity_pool_supply: pool
            .liquidity_pool_supply
            .checked_add(delta_lp)
            .expect("liquidity pool supply overflows u128"),
        reserve_a: pool
            .reserve_a
            .checked_add(actual_amount_a)
            .expect("reserve A overflows u128"),
        reserve_b: pool
            .reserve_b
            .checked_add(actual_amount_b)
            .expect("reserve B overflows u128"),
        ..pool.clone()
    }
}
