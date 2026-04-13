pub use amm_core::{PoolDefinition, compute_liquidity_token_pda_seed, compute_vault_pda_seed};
use nssa_core::{
    account::{AccountId, AccountWithMetadata, Data},
    program::{AccountPostState, ChainedCall},
};

/// Validates swap setup: checks pool is active, vaults match, and reserves are sufficient.
fn validate_swap_setup(
    pool: &AccountWithMetadata,
    vault_a: &AccountWithMetadata,
    vault_b: &AccountWithMetadata,
) -> PoolDefinition {
    let pool_def_data = PoolDefinition::try_from(&pool.account.data)
        .expect("AMM Program expects a valid Pool Definition Account");

    assert!(pool_def_data.active, "Pool is inactive");
    assert_eq!(
        vault_a.account_id, pool_def_data.vault_a_id,
        "Vault A was not provided"
    );
    assert_eq!(
        vault_b.account_id, pool_def_data.vault_b_id,
        "Vault B was not provided"
    );

    let vault_a_token_holding = token_core::TokenHolding::try_from(&vault_a.account.data)
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

    let vault_b_token_holding = token_core::TokenHolding::try_from(&vault_b.account.data)
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

    pool_def_data
}

/// Creates post-state and returns reserves after swap.
#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "consistent with codebase style"
)]
fn create_swap_post_states(
    pool: AccountWithMetadata,
    pool_def_data: PoolDefinition,
    vault_a: AccountWithMetadata,
    vault_b: AccountWithMetadata,
    user_holding_a: AccountWithMetadata,
    user_holding_b: AccountWithMetadata,
    deposit_a: u128,
    withdraw_a: u128,
    deposit_b: u128,
    withdraw_b: u128,
) -> Vec<AccountPostState> {
    let mut pool_post = pool.account;
    let pool_post_definition = PoolDefinition {
        reserve_a: pool_def_data.reserve_a + deposit_a - withdraw_a,
        reserve_b: pool_def_data.reserve_b + deposit_b - withdraw_b,
        ..pool_def_data
    };

    pool_post.data = Data::from(&pool_post_definition);

    vec![
        AccountPostState::new(pool_post),
        AccountPostState::new(vault_a.account),
        AccountPostState::new(vault_b.account),
        AccountPostState::new(user_holding_a.account),
        AccountPostState::new(user_holding_b.account),
    ]
}

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
#[must_use]
pub fn swap_exact_input(
    pool: AccountWithMetadata,
    vault_a: AccountWithMetadata,
    vault_b: AccountWithMetadata,
    user_holding_a: AccountWithMetadata,
    user_holding_b: AccountWithMetadata,
    swap_amount_in: u128,
    min_amount_out: u128,
    token_in_id: AccountId,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    let pool_def_data = validate_swap_setup(&pool, &vault_a, &vault_b);

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

    let post_states = create_swap_post_states(
        pool,
        pool_def_data,
        vault_a,
        vault_b,
        user_holding_a,
        user_holding_b,
        deposit_a,
        withdraw_a,
        deposit_b,
        withdraw_b,
    );

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

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
#[must_use]
pub fn swap_exact_output(
    pool: AccountWithMetadata,
    vault_a: AccountWithMetadata,
    vault_b: AccountWithMetadata,
    user_holding_a: AccountWithMetadata,
    user_holding_b: AccountWithMetadata,
    exact_amount_out: u128,
    max_amount_in: u128,
    token_in_id: AccountId,
) -> (Vec<AccountPostState>, Vec<ChainedCall>) {
    let pool_def_data = validate_swap_setup(&pool, &vault_a, &vault_b);

    let (chained_calls, [deposit_a, withdraw_a], [deposit_b, withdraw_b]) =
        if token_in_id == pool_def_data.definition_token_a_id {
            let (chained_calls, deposit_a, withdraw_b) = exact_output_swap_logic(
                user_holding_a.clone(),
                vault_a.clone(),
                vault_b.clone(),
                user_holding_b.clone(),
                exact_amount_out,
                max_amount_in,
                pool_def_data.reserve_a,
                pool_def_data.reserve_b,
                pool.account_id,
            );

            (chained_calls, [deposit_a, 0], [0, withdraw_b])
        } else if token_in_id == pool_def_data.definition_token_b_id {
            let (chained_calls, deposit_b, withdraw_a) = exact_output_swap_logic(
                user_holding_b.clone(),
                vault_b.clone(),
                vault_a.clone(),
                user_holding_a.clone(),
                exact_amount_out,
                max_amount_in,
                pool_def_data.reserve_b,
                pool_def_data.reserve_a,
                pool.account_id,
            );

            (chained_calls, [0, withdraw_a], [deposit_b, 0])
        } else {
            panic!("AccountId is not a token type for the pool");
        };

    let post_states = create_swap_post_states(
        pool,
        pool_def_data,
        vault_a,
        vault_b,
        user_holding_a,
        user_holding_b,
        deposit_a,
        withdraw_a,
        deposit_b,
        withdraw_b,
    );

    (post_states, chained_calls)
}

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
fn exact_output_swap_logic(
    user_deposit: AccountWithMetadata,
    vault_deposit: AccountWithMetadata,
    vault_withdraw: AccountWithMetadata,
    user_withdraw: AccountWithMetadata,
    exact_amount_out: u128,
    max_amount_in: u128,
    reserve_deposit_vault_amount: u128,
    reserve_withdraw_vault_amount: u128,
    pool_id: AccountId,
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

    let token_program_id = user_deposit.account.program_owner;

    let mut chained_calls = Vec::new();
    chained_calls.push(ChainedCall::new(
        token_program_id,
        vec![user_deposit, vault_deposit],
        &token_core::Instruction::Transfer {
            amount_to_transfer: deposit_amount,
        },
    ));

    let mut vault_withdraw = vault_withdraw;
    vault_withdraw.is_authorized = true;

    let pda_seed = compute_vault_pda_seed(
        pool_id,
        token_core::TokenHolding::try_from(&vault_withdraw.account.data)
            .expect("Exact Output Swap Logic: AMM Program expects valid token data")
            .definition_id(),
    );

    chained_calls.push(
        ChainedCall::new(
            token_program_id,
            vec![vault_withdraw, user_withdraw],
            &token_core::Instruction::Transfer {
                amount_to_transfer: exact_amount_out,
            },
        )
        .with_pda_seeds(vec![pda_seed]),
    );

    (chained_calls, deposit_amount, exact_amount_out)
}
