use std::num::NonZeroU128;

use amm_core::{PoolDefinition, compute_liquidity_token_pda_seed, compute_vault_pda_seed};
use lee_core::{
    account::{AccountDiff, AccountWithMetadata, BalanceDiff, Data},
    program::{AccountDiffOutput, ChainedCall},
};

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
#[must_use]
pub fn remove_liquidity(
    pool: &AccountWithMetadata,
    vault_a: &AccountWithMetadata,
    vault_b: &AccountWithMetadata,
    pool_definition_lp: &AccountWithMetadata,
    user_holding_a: &AccountWithMetadata,
    user_holding_b: &AccountWithMetadata,
    user_holding_lp: &AccountWithMetadata,
    remove_liquidity_amount: NonZeroU128,
    min_amount_to_remove_token_a: u128,
    min_amount_to_remove_token_b: u128,
) -> (Vec<AccountDiffOutput>, Vec<ChainedCall>) {
    let remove_liquidity_amount: u128 = remove_liquidity_amount.into();

    // 1. Fetch Pool state
    let pool_def_data = PoolDefinition::try_from(&pool.account.data)
        .expect("Remove liquidity: AMM Program expects a valid Pool Definition Account");

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

    assert!(
        min_amount_to_remove_token_a != 0,
        "Minimum withdraw amount must be nonzero"
    );
    assert!(
        min_amount_to_remove_token_b != 0,
        "Minimum withdraw amount must be nonzero"
    );

    // 2. Compute withdrawal amounts
    let user_holding_lp_data = token_core::TokenHolding::try_from(&user_holding_lp.account.data)
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

    let token_program_id: lee_core::program::ProgramId =
        user_holding_a.account.program_owner.into();

    // Chaincall for Token A withdraw
    let call_token_a = ChainedCall::new(
        token_program_id,
        vec![vault_a.account_id, user_holding_a.account_id],
        &token_core::Instruction::Transfer {
            amount_to_transfer: withdraw_amount_a,
        },
    )
    .with_pda_seeds(vec![compute_vault_pda_seed(
        pool.account_id,
        pool_def_data.definition_token_a_id,
    )]);
    // Chaincall for Token B withdraw
    let call_token_b = ChainedCall::new(
        token_program_id,
        vec![vault_b.account_id, user_holding_b.account_id],
        &token_core::Instruction::Transfer {
            amount_to_transfer: withdraw_amount_b,
        },
    )
    .with_pda_seeds(vec![compute_vault_pda_seed(
        pool.account_id,
        pool_def_data.definition_token_b_id,
    )]);
    // Chaincall for LP adjustment
    let call_token_lp = ChainedCall::new(
        token_program_id,
        vec![pool_definition_lp.account_id, user_holding_lp.account_id],
        &token_core::Instruction::Burn {
            amount_to_burn: delta_lp,
        },
    )
    .with_pda_seeds(vec![compute_liquidity_token_pda_seed(pool.account_id)]);

    let chained_calls = vec![call_token_lp, call_token_b, call_token_a];

    let post_states = vec![
        AccountDiffOutput::new(AccountDiff {
            id: pool.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(Data::from(&pool_post_definition)),
        }),
        AccountDiffOutput::new(AccountDiff::unchanged(vault_a.account_id)),
        AccountDiffOutput::new(AccountDiff::unchanged(vault_b.account_id)),
        AccountDiffOutput::new(AccountDiff::unchanged(pool_definition_lp.account_id)),
        AccountDiffOutput::new(AccountDiff::unchanged(user_holding_a.account_id)),
        AccountDiffOutput::new(AccountDiff::unchanged(user_holding_b.account_id)),
        AccountDiffOutput::new(AccountDiff::unchanged(user_holding_lp.account_id)),
    ];

    (post_states, chained_calls)
}
