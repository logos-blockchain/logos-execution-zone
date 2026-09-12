pub use amm_core::PoolDefinition;
use lee_core::{
    account::{AccountId, BalanceDiff, ShardData},
    program::{AccountInput, AccountStateDiff, ChainedCall, PdaSeed},
};
use token_core::HoldingTarget;

/// Validates swap setup: checks pool is active, vaults match, and reserves are sufficient.
fn validate_swap_setup(
    pool: &AccountInput,
    vault_a: &AccountInput,
    vault_b: &AccountInput,
    user_owner: &AccountInput,
    self_account_id: AccountId,
    user: &HoldingTarget,
) -> (PoolDefinition, PdaSeed) {
    let pool_def_data = PoolDefinition::try_from(pool.shard_of(self_account_id))
        .expect("AMM Program expects a valid Pool Definition Account");
    let pool_seed = crate::pool_seed(pool, &pool_def_data, self_account_id);

    assert!(pool_def_data.active, "Pool is inactive");
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

    let vault_a_token_holding =
        token_core::TokenHolding::try_from(vault_a.shard_of(pool_def_data.token_program_id))
            .expect("AMM Program expects a valid Token Holding Account for Vault A");
    let token_core::TokenHolding::Fungible {
        definition_id: _,
        balance: vault_a_balance,
    } = vault_a_token_holding
    else {
        panic!("AMM Program expects a valid Fungible Token Holding Account for Vault A");
    };

    assert!(
        vault_a_balance >= pool_def_data.reserve_a,
        "Reserve for Token A exceeds vault balance"
    );

    let vault_b_token_holding =
        token_core::TokenHolding::try_from(vault_b.shard_of(pool_def_data.token_program_id))
            .expect("AMM Program expects a valid Token Holding Account for Vault B");
    let token_core::TokenHolding::Fungible {
        definition_id: _,
        balance: vault_b_balance,
    } = vault_b_token_holding
    else {
        panic!("AMM Program expects a valid Fungible Token Holding Account for Vault B");
    };

    assert!(
        vault_b_balance >= pool_def_data.reserve_b,
        "Reserve for Token B exceeds vault balance"
    );

    (pool_def_data, pool_seed)
}

/// Creates post-state and returns reserves after swap.
#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "consistent with codebase style"
)]
fn create_swap_post_diffs(
    pool: AccountInput,
    pool_def_data: PoolDefinition,
    vault_a: AccountInput,
    vault_b: AccountInput,
    user_holding_a: AccountInput,
    user_holding_b: AccountInput,
    user_owner: AccountInput,
    deposit_a: u128,
    withdraw_a: u128,
    deposit_b: u128,
    withdraw_b: u128,
) -> Vec<AccountStateDiff> {
    let pool_post_definition = PoolDefinition {
        reserve_a: pool_def_data.reserve_a + deposit_a - withdraw_a,
        reserve_b: pool_def_data.reserve_b + deposit_b - withdraw_b,
        ..pool_def_data
    };

    vec![
        AccountStateDiff::new(
            pool,
            BalanceDiff::Add(0),
            ShardData::from(&pool_post_definition),
        ),
        AccountStateDiff::unchanged(vault_a),
        AccountStateDiff::unchanged(vault_b),
        AccountStateDiff::unchanged(user_holding_a),
        AccountStateDiff::unchanged(user_holding_b),
        AccountStateDiff::unchanged(user_owner),
    ]
}

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
#[must_use]
pub fn swap_exact_input(
    pool: AccountInput,
    vault_a: AccountInput,
    vault_b: AccountInput,
    user_holding_a: AccountInput,
    user_holding_b: AccountInput,
    user_owner: AccountInput,
    swap_amount_in: u128,
    min_amount_out: u128,
    token_in_id: AccountId,
    self_account_id: AccountId,
    user: &HoldingTarget,
) -> (Vec<AccountStateDiff>, Vec<ChainedCall>) {
    let (pool_def_data, pool_seed) = validate_swap_setup(
        &pool,
        &vault_a,
        &vault_b,
        &user_owner,
        self_account_id,
        user,
    );

    let (chained_calls, [deposit_a, withdraw_a], [deposit_b, withdraw_b]) =
        if token_in_id == pool_def_data.definition_token_a_id {
            let (chained_calls, deposit_a, withdraw_b) = swap_logic(
                &user_holding_a,
                &vault_a,
                &vault_b,
                &user_holding_b,
                swap_amount_in,
                min_amount_out,
                pool_def_data.reserve_a,
                pool_def_data.reserve_b,
                pool.account_id,
                pool_seed,
                pool_def_data.token_program_id,
                user,
            );

            (chained_calls, [deposit_a, 0], [0, withdraw_b])
        } else if token_in_id == pool_def_data.definition_token_b_id {
            let (chained_calls, deposit_b, withdraw_a) = swap_logic(
                &user_holding_b,
                &vault_b,
                &vault_a,
                &user_holding_a,
                swap_amount_in,
                min_amount_out,
                pool_def_data.reserve_b,
                pool_def_data.reserve_a,
                pool.account_id,
                pool_seed,
                pool_def_data.token_program_id,
                user,
            );

            (chained_calls, [0, withdraw_a], [deposit_b, 0])
        } else {
            panic!("AccountId is not a token type for the pool");
        };

    let post_diffs = create_swap_post_diffs(
        pool,
        pool_def_data,
        vault_a,
        vault_b,
        user_holding_a,
        user_holding_b,
        user_owner,
        deposit_a,
        withdraw_a,
        deposit_b,
        withdraw_b,
    );

    (post_diffs, chained_calls)
}

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
fn swap_logic(
    user_deposit: &AccountInput,
    vault_deposit: &AccountInput,
    vault_withdraw: &AccountInput,
    user_withdraw: &AccountInput,
    swap_amount_in: u128,
    min_amount_out: u128,
    reserve_deposit_vault_amount: u128,
    reserve_withdraw_vault_amount: u128,
    pool_id: AccountId,
    pool_seed: PdaSeed,
    token_program_id: AccountId,
    user: &HoldingTarget,
) -> (Vec<ChainedCall>, u128, u128) {
    // Compute withdraw amount
    // Maintains pool constant product
    // k = pool_def_data.reserve_a * pool_def_data.reserve_b;
    let withdraw_amount = reserve_withdraw_vault_amount
        .checked_mul(swap_amount_in)
        .expect("reserve * amount_in overflows u128")
        / (reserve_deposit_vault_amount + swap_amount_in);

    // Slippage check
    assert!(
        min_amount_out <= withdraw_amount,
        "Withdraw amount is less than minimal amount out"
    );
    assert!(withdraw_amount != 0, "Withdraw amount should be nonzero");

    let chained_calls = vec![
        crate::deposit(
            token_program_id,
            user_deposit,
            vault_deposit,
            user,
            pool_id,
            swap_amount_in,
        ),
        crate::withdraw(
            token_program_id,
            vault_withdraw,
            user_withdraw,
            user,
            pool_id,
            pool_seed,
            withdraw_amount,
        ),
    ];

    (chained_calls, swap_amount_in, withdraw_amount)
}

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
#[must_use]
pub fn swap_exact_output(
    pool: AccountInput,
    vault_a: AccountInput,
    vault_b: AccountInput,
    user_holding_a: AccountInput,
    user_holding_b: AccountInput,
    user_owner: AccountInput,
    exact_amount_out: u128,
    max_amount_in: u128,
    token_in_id: AccountId,
    self_account_id: AccountId,
    user: &HoldingTarget,
) -> (Vec<AccountStateDiff>, Vec<ChainedCall>) {
    let (pool_def_data, pool_seed) = validate_swap_setup(
        &pool,
        &vault_a,
        &vault_b,
        &user_owner,
        self_account_id,
        user,
    );

    let (chained_calls, [deposit_a, withdraw_a], [deposit_b, withdraw_b]) =
        if token_in_id == pool_def_data.definition_token_a_id {
            let (chained_calls, deposit_a, withdraw_b) = exact_output_swap_logic(
                &user_holding_a,
                &vault_a,
                &vault_b,
                &user_holding_b,
                exact_amount_out,
                max_amount_in,
                pool_def_data.reserve_a,
                pool_def_data.reserve_b,
                pool.account_id,
                pool_seed,
                pool_def_data.token_program_id,
                user,
            );

            (chained_calls, [deposit_a, 0], [0, withdraw_b])
        } else if token_in_id == pool_def_data.definition_token_b_id {
            let (chained_calls, deposit_b, withdraw_a) = exact_output_swap_logic(
                &user_holding_b,
                &vault_b,
                &vault_a,
                &user_holding_a,
                exact_amount_out,
                max_amount_in,
                pool_def_data.reserve_b,
                pool_def_data.reserve_a,
                pool.account_id,
                pool_seed,
                pool_def_data.token_program_id,
                user,
            );

            (chained_calls, [0, withdraw_a], [deposit_b, 0])
        } else {
            panic!("AccountId is not a token type for the pool");
        };

    let post_diffs = create_swap_post_diffs(
        pool,
        pool_def_data,
        vault_a,
        vault_b,
        user_holding_a,
        user_holding_b,
        user_owner,
        deposit_a,
        withdraw_a,
        deposit_b,
        withdraw_b,
    );

    (post_diffs, chained_calls)
}

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
fn exact_output_swap_logic(
    user_deposit: &AccountInput,
    vault_deposit: &AccountInput,
    vault_withdraw: &AccountInput,
    user_withdraw: &AccountInput,
    exact_amount_out: u128,
    max_amount_in: u128,
    reserve_deposit_vault_amount: u128,
    reserve_withdraw_vault_amount: u128,
    pool_id: AccountId,
    pool_seed: PdaSeed,
    token_program_id: AccountId,
    user: &HoldingTarget,
) -> (Vec<ChainedCall>, u128, u128) {
    // Guard: exact_amount_out must be nonzero
    assert_ne!(exact_amount_out, 0, "Exact amount out must be nonzero");

    // Guard: exact_amount_out must be less than reserve_withdraw_vault_amount
    assert!(
        exact_amount_out < reserve_withdraw_vault_amount,
        "Exact amount out exceeds reserve"
    );

    // Compute deposit amount using ceiling division
    // Formula: amount_in = ceil(reserve_in * exact_amount_out / (reserve_out - exact_amount_out))
    let deposit_amount = reserve_deposit_vault_amount
        .checked_mul(exact_amount_out)
        .expect("reserve * amount_out overflows u128")
        .div_ceil(reserve_withdraw_vault_amount - exact_amount_out);

    // Slippage check
    assert!(
        deposit_amount <= max_amount_in,
        "Required input exceeds maximum amount in"
    );

    let chained_calls = vec![
        crate::deposit(
            token_program_id,
            user_deposit,
            vault_deposit,
            user,
            pool_id,
            deposit_amount,
        ),
        crate::withdraw(
            token_program_id,
            vault_withdraw,
            user_withdraw,
            user,
            pool_id,
            pool_seed,
            exact_amount_out,
        ),
    ];

    (chained_calls, deposit_amount, exact_amount_out)
}
