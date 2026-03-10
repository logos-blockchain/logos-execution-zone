pub use amm_core::{PoolDefinition, compute_liquidity_token_pda_seed, compute_vault_pda_seed};
use nssa_core::{
    account::{AccountId, AccountWithMetadata, Data},
    program::{AccountPostState, ChainedCall},
};

use crate::vault_utils::read_vault_fungible_balances;

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
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

    // fetch pool reserves
    // validates reserves is at least the vaults' balances
    let (vault_a_balance, vault_b_balance) = read_vault_fungible_balances(&vault_a, &vault_b);

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

    // Update pool account
    let mut pool_post = pool.account.clone();
    let pool_post_definition = PoolDefinition {
        reserve_a: pool_def_data.reserve_a + deposit_a - withdraw_a,
        reserve_b: pool_def_data.reserve_b + deposit_b - withdraw_b,
        ..pool_def_data
    };

    pool_post.data = Data::from(&pool_post_definition);

    let post_states = vec![
        AccountPostState::new(pool_post.clone()),
        AccountPostState::new(vault_a.account.clone()),
        AccountPostState::new(vault_b.account.clone()),
        AccountPostState::new(user_holding_a.account.clone()),
        AccountPostState::new(user_holding_b.account.clone()),
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
    let withdraw_amount = (reserve_withdraw_vault_amount * swap_amount_in)
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

    let mut vault_withdraw = vault_withdraw.clone();
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
