pub use amm_core::{PoolDefinition, compute_liquidity_token_pda_seed, compute_vault_pda_seed};
use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, ShardData},
    program::{AccountMeta, Plan, Proposed},
};

use crate::{Effect, transfer_call};

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SwapBinding {
    pub token_program_id: AccountId,
    pub vault_a_id: AccountId,
    pub vault_b_id: AccountId,
    pub input_is_token_a: bool,
    pub definition_id_in: AccountId,
    pub definition_id_out: AccountId,
    pub amount_in: u128,
    pub amount_out: u128,
    pub reserve_bound_a: u128,
    pub reserve_bound_b: u128,
}

pub fn swap_exact_input(
    plan: &mut Plan,
    accounts: &[AccountMeta; 5],
    min_amount_out: u128,
    binding: SwapBinding,
) {
    let proposal = Proposed::new(binding);

    // An `amount_out` the pool never priced is a vault drain: the withdraw leg pays it out of
    // reserves that never backed it. `require` emits the pool's effect before it hands the value
    // back, so the guard cannot be forgotten on the way to the withdraw leg. Nothing in the types
    // checks that this particular effect validates this particular value — that pairing is the
    // caller's to get right, and `Effect::SwapExactInput` is what enforces it at resolution.
    let route = plan
        .require(&accounts[0], &Effect::SwapExactInput(binding), proposal)
        .get();

    assert!(
        min_amount_out <= route.amount_out,
        "Withdraw amount is less than minimal amount out"
    );
    assert!(route.amount_out != 0, "Withdraw amount should be nonzero");

    plan_swap_legs(plan, accounts, &route);
}

pub fn swap_exact_output(
    plan: &mut Plan,
    accounts: &[AccountMeta; 5],
    max_amount_in: u128,
    binding: SwapBinding,
) {
    assert_ne!(binding.amount_out, 0, "Exact amount out must be nonzero");

    let proposal = Proposed::new(binding);

    let route = plan
        .require(&accounts[0], &Effect::SwapExactOutput(binding), proposal)
        .get();

    assert!(
        route.amount_in <= max_amount_in,
        "Required input exceeds maximum amount in"
    );

    plan_swap_legs(plan, accounts, &route);
}

fn plan_swap_legs(plan: &mut Plan, accounts: &[AccountMeta; 5], route: &SwapBinding) {
    let [pool, vault_a, vault_b, user_holding_a, user_holding_b] = accounts;

    plan.effect(
        vault_a,
        &Effect::VaultCovers {
            token_program_id: route.token_program_id,
            minimum: route.reserve_bound_a,
        },
    );
    plan.effect(
        vault_b,
        &Effect::VaultCovers {
            token_program_id: route.token_program_id,
            minimum: route.reserve_bound_b,
        },
    );

    let (user_deposit, vault_deposit, vault_withdraw, user_withdraw) = if route.input_is_token_a {
        (user_holding_a, vault_a, vault_b, user_holding_b)
    } else {
        (user_holding_b, vault_b, vault_a, user_holding_a)
    };

    plan.call(transfer_call(
        route.token_program_id,
        user_deposit,
        vault_deposit,
        route.definition_id_in,
        route.amount_in,
    ));
    plan.call(
        transfer_call(
            route.token_program_id,
            vault_withdraw,
            user_withdraw,
            route.definition_id_out,
            route.amount_out,
        )
        .with_pda_seeds(vec![compute_vault_pda_seed(
            pool.account_id,
            route.definition_id_out,
        )]),
    );
}

#[must_use]
pub fn pool_after_exact_input(pre_data: &ShardData, binding: &SwapBinding) -> ShardData {
    let pool = decode_active_pool(pre_data, binding);
    let (reserve_in, reserve_out) = oriented_reserves(&pool, binding);

    let withdraw_amount = amm_core::quote_exact_input(reserve_in, reserve_out, binding.amount_in)
        .expect("reserve * amount_in overflows u128");

    assert_eq!(
        withdraw_amount, binding.amount_out,
        "Proposed output does not match the pool's exact-input price"
    );

    swapped_pool(&pool, binding, binding.amount_in, withdraw_amount)
}

#[must_use]
pub fn pool_after_exact_output(pre_data: &ShardData, binding: &SwapBinding) -> ShardData {
    let pool = decode_active_pool(pre_data, binding);
    let (reserve_in, reserve_out) = oriented_reserves(&pool, binding);

    assert!(
        binding.amount_out < reserve_out,
        "Exact amount out exceeds reserve"
    );

    let deposit_amount = amm_core::quote_exact_output(reserve_in, reserve_out, binding.amount_out)
        .expect("reserve * amount_out overflows u128");

    assert_eq!(
        deposit_amount, binding.amount_in,
        "Proposed input does not match the pool's exact-output price"
    );

    swapped_pool(&pool, binding, deposit_amount, binding.amount_out)
}

pub fn vault_covers(pre_data: &ShardData, minimum: u128) {
    let token_core::TokenHolding::Fungible { balance, .. } =
        token_core::TokenHolding::try_from(pre_data)
            .expect("AMM Program expects a valid Token Holding Account for the vault")
    else {
        panic!("AMM Program expects a valid Fungible Token Holding Account for the vault");
    };

    assert!(
        balance >= minimum,
        "Reserve bound exceeds the vault's balance"
    );
}

fn decode_active_pool(pre_data: &ShardData, binding: &SwapBinding) -> PoolDefinition {
    let pool = PoolDefinition::try_from(pre_data)
        .expect("AMM Program expects a valid Pool Definition Account");

    assert!(pool.active, "Pool is inactive");
    assert_eq!(
        pool.token_program_id, binding.token_program_id,
        "Swap routes through a token program the pool does not use"
    );
    assert_eq!(
        binding.vault_a_id, pool.vault_a_id,
        "Vault A was not provided"
    );
    assert_eq!(
        binding.vault_b_id, pool.vault_b_id,
        "Vault B was not provided"
    );
    assert!(
        pool.reserve_a <= binding.reserve_bound_a,
        "Reserve for Token A exceeds the bound the vault was checked against"
    );
    assert!(
        pool.reserve_b <= binding.reserve_bound_b,
        "Reserve for Token B exceeds the bound the vault was checked against"
    );

    pool
}

fn oriented_reserves(pool: &PoolDefinition, binding: &SwapBinding) -> (u128, u128) {
    let (definition_id_in, definition_id_out, reserve_in, reserve_out) = if binding.input_is_token_a
    {
        (
            pool.definition_token_a_id,
            pool.definition_token_b_id,
            pool.reserve_a,
            pool.reserve_b,
        )
    } else {
        (
            pool.definition_token_b_id,
            pool.definition_token_a_id,
            pool.reserve_b,
            pool.reserve_a,
        )
    };

    assert_eq!(
        binding.definition_id_in, definition_id_in,
        "AccountId is not a token type for the pool"
    );
    assert_eq!(
        binding.definition_id_out, definition_id_out,
        "AccountId is not a token type for the pool"
    );

    (reserve_in, reserve_out)
}

fn swapped_pool(
    pool: &PoolDefinition,
    binding: &SwapBinding,
    amount_in: u128,
    amount_out: u128,
) -> ShardData {
    let (reserve_a, reserve_b) = if binding.input_is_token_a {
        (pool.reserve_a + amount_in, pool.reserve_b - amount_out)
    } else {
        (pool.reserve_a - amount_out, pool.reserve_b + amount_in)
    };

    ShardData::from(&PoolDefinition {
        reserve_a,
        reserve_b,
        ..*pool
    })
}
