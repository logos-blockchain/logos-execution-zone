use amm_core::{PoolDefinition, compute_liquidity_token_pda_seed, compute_vault_pda_seed};
use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, ProgramShardSelector, ShardData},
    program::{AccountMeta, ChainedCall, Plan, Proposed},
};
use token_core::TokenKind;

use crate::{Effect, transfer_call};

#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RemoveBinding {
    pub token_program_id: AccountId,
    pub vault_a_id: AccountId,
    pub vault_b_id: AccountId,
    pub liquidity_pool_id: AccountId,
    pub definition_token_a_id: AccountId,
    pub definition_token_b_id: AccountId,
    pub remove_liquidity_amount: u128,
    pub amount_to_remove_token_a: u128,
    pub amount_to_remove_token_b: u128,
    pub amount_liquidity_burned: u128,
    pub liquidity_supply_bound: u128,
}

// Everything a removal sends outside the pool's own shard, including the definitions whose vault
// PDA seeds authorize the withdrawals. Reachable only from a `Checked` copy.
#[derive(Clone, Copy)]
struct Withdrawal {
    token_program_id: AccountId,
    definition_token_a_id: AccountId,
    definition_token_b_id: AccountId,
    amount_to_remove_token_a: u128,
    amount_to_remove_token_b: u128,
    amount_liquidity_burned: u128,
    liquidity_pool_id: AccountId,
    liquidity_supply_bound: u128,
}

impl From<&RemoveBinding> for Withdrawal {
    fn from(binding: &RemoveBinding) -> Self {
        Self {
            token_program_id: binding.token_program_id,
            definition_token_a_id: binding.definition_token_a_id,
            definition_token_b_id: binding.definition_token_b_id,
            amount_to_remove_token_a: binding.amount_to_remove_token_a,
            amount_to_remove_token_b: binding.amount_to_remove_token_b,
            amount_liquidity_burned: binding.amount_liquidity_burned,
            liquidity_pool_id: binding.liquidity_pool_id,
            liquidity_supply_bound: binding.liquidity_supply_bound,
        }
    }
}

pub fn remove_liquidity(
    plan: &mut Plan,
    accounts: &[AccountMeta; 7],
    min_amount_to_remove_token_a: u128,
    min_amount_to_remove_token_b: u128,
    binding: RemoveBinding,
) {
    let [
        pool,
        vault_a,
        vault_b,
        pool_definition_lp,
        user_holding_a,
        user_holding_b,
        user_holding_lp,
    ] = accounts;

    assert!(
        binding.remove_liquidity_amount != 0,
        "Remove liquidity amount must be nonzero"
    );
    assert!(
        min_amount_to_remove_token_a != 0,
        "Minimum withdraw amount must be nonzero"
    );
    assert!(
        min_amount_to_remove_token_b != 0,
        "Minimum withdraw amount must be nonzero"
    );

    let proposal = Proposed::new(Withdrawal::from(&binding));
    let withdrawal = plan
        .require(pool, &Effect::RemoveLiquidity(binding), proposal)
        .get();

    // The pool effect requires the real supply to be at least this bound and this guard requires
    // the holding to be at most the same bound, which together reproduce the cross-account
    // `user_lp_balance <= liquidity_pool_supply` the single-`Execute` version could read directly.
    plan.effect(
        user_holding_lp,
        &Effect::LiquidityHoldingIsBounded {
            token_program_id: withdrawal.token_program_id,
            definition_id: withdrawal.liquidity_pool_id,
            maximum: withdrawal.liquidity_supply_bound,
        },
    );

    assert!(
        withdrawal.amount_to_remove_token_a >= min_amount_to_remove_token_a,
        "Insufficient minimal withdraw amount (Token A) provided for liquidity amount"
    );
    assert!(
        withdrawal.amount_to_remove_token_b >= min_amount_to_remove_token_b,
        "Insufficient minimal withdraw amount (Token B) provided for liquidity amount"
    );

    plan.call(
        ChainedCall::new(
            withdrawal.token_program_id,
            vec![
                ProgramShardSelector::from(pool_definition_lp),
                ProgramShardSelector::from(user_holding_lp),
            ],
            &token_core::Instruction::Burn {
                amount_to_burn: withdrawal.amount_liquidity_burned,
                kind: TokenKind::Fungible,
            },
        )
        .with_pda_seeds(vec![compute_liquidity_token_pda_seed(pool.account_id)]),
    );
    plan.call(
        transfer_call(
            withdrawal.token_program_id,
            vault_b,
            user_holding_b,
            withdrawal.definition_token_b_id,
            withdrawal.amount_to_remove_token_b,
        )
        .with_pda_seeds(vec![compute_vault_pda_seed(
            pool.account_id,
            withdrawal.definition_token_b_id,
        )]),
    );
    plan.call(
        transfer_call(
            withdrawal.token_program_id,
            vault_a,
            user_holding_a,
            withdrawal.definition_token_a_id,
            withdrawal.amount_to_remove_token_a,
        )
        .with_pda_seeds(vec![compute_vault_pda_seed(
            pool.account_id,
            withdrawal.definition_token_a_id,
        )]),
    );
}

#[must_use]
pub fn pool_after_remove(pre_data: &ShardData, binding: &RemoveBinding) -> ShardData {
    let pool = PoolDefinition::try_from(pre_data)
        .expect("Remove liquidity: AMM Program expects a valid Pool Definition Account");

    assert!(pool.active, "Pool is inactive");
    assert_eq!(
        pool.token_program_id, binding.token_program_id,
        "Remove liquidity routes through a token program the pool does not use"
    );
    assert_eq!(
        pool.liquidity_pool_id, binding.liquidity_pool_id,
        "LP definition mismatch"
    );
    assert_eq!(
        binding.vault_a_id, pool.vault_a_id,
        "Vault A was not provided"
    );
    assert_eq!(
        binding.vault_b_id, pool.vault_b_id,
        "Vault B was not provided"
    );
    assert_eq!(
        binding.definition_token_a_id, pool.definition_token_a_id,
        "Token A definition is not the pool's"
    );
    assert_eq!(
        binding.definition_token_b_id, pool.definition_token_b_id,
        "Token B definition is not the pool's"
    );
    assert!(
        pool.liquidity_pool_supply >= binding.liquidity_supply_bound,
        "Invalid liquidity account provided"
    );

    let withdraw_amount_a = amm_core::withdrawal_share(
        pool.reserve_a,
        binding.remove_liquidity_amount,
        pool.liquidity_pool_supply,
    )
    .expect("reserve * liquidity amount overflows u128");
    let withdraw_amount_b = amm_core::withdrawal_share(
        pool.reserve_b,
        binding.remove_liquidity_amount,
        pool.liquidity_pool_supply,
    )
    .expect("reserve * liquidity amount overflows u128");

    assert_eq!(
        withdraw_amount_a, binding.amount_to_remove_token_a,
        "Proposed Token A withdrawal does not match the pool's removal calculation"
    );
    assert_eq!(
        withdraw_amount_b, binding.amount_to_remove_token_b,
        "Proposed Token B withdrawal does not match the pool's removal calculation"
    );

    let delta_lp = amm_core::withdrawal_share(
        pool.liquidity_pool_supply,
        binding.remove_liquidity_amount,
        pool.liquidity_pool_supply,
    )
    .expect("supply * liquidity amount overflows u128");

    assert_eq!(
        delta_lp, binding.amount_liquidity_burned,
        "Proposed LP burn does not match the pool's removal calculation"
    );

    let liquidity_pool_supply = pool.liquidity_pool_supply - delta_lp;

    ShardData::from(&PoolDefinition {
        liquidity_pool_supply,
        reserve_a: pool.reserve_a - withdraw_amount_a,
        reserve_b: pool.reserve_b - withdraw_amount_b,
        active: liquidity_pool_supply != 0,
        ..pool
    })
}

pub fn liquidity_holding_is_bounded(pre_data: &ShardData, definition_id: AccountId, maximum: u128) {
    let token_core::TokenHolding::Fungible {
        definition_id: holding_definition_id,
        balance,
    } = token_core::TokenHolding::try_from(pre_data)
        .expect("Remove liquidity: AMM Program expects a valid Token Account for liquidity token")
    else {
        panic!(
            "Remove liquidity: AMM Program expects a valid Fungible Token Holding Account for liquidity token"
        );
    };

    assert!(balance <= maximum, "Invalid liquidity account provided");
    assert_eq!(
        holding_definition_id, definition_id,
        "Invalid liquidity account provided"
    );
}
