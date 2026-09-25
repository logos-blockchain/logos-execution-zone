use amm_core::{PoolDefinition, compute_vault_pda_seed};
use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, ProgramShardSelector, ShardData},
    program::{AccountMeta, ChainedCall, Plan},
};
use token_core::TokenKind;

use crate::{Effect, transfer_call};

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
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
}

pub fn remove_liquidity(plan: &mut Plan, accounts: &[AccountMeta; 7], binding: RemoveBinding) {
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
        binding.amount_to_remove_token_a != 0 && binding.amount_to_remove_token_b != 0,
        "Withdraw amounts must be nonzero"
    );

    plan.effect(pool, &Effect::RemoveLiquidity(binding));

    plan.call(ChainedCall::new(
        binding.token_program_id,
        vec![
            ProgramShardSelector::from(pool_definition_lp),
            ProgramShardSelector::from(user_holding_lp),
        ],
        &token_core::Instruction::Burn {
            amount_to_burn: binding.remove_liquidity_amount,
            kind: TokenKind::Fungible,
        },
    ));
    plan.call(
        transfer_call(
            binding.token_program_id,
            vault_b,
            user_holding_b,
            binding.definition_token_b_id,
            binding.amount_to_remove_token_b,
        )
        .with_pda_seeds(vec![compute_vault_pda_seed(
            pool.account_id,
            binding.definition_token_b_id,
        )]),
    );
    plan.call(
        transfer_call(
            binding.token_program_id,
            vault_a,
            user_holding_a,
            binding.definition_token_a_id,
            binding.amount_to_remove_token_a,
        )
        .with_pda_seeds(vec![compute_vault_pda_seed(
            pool.account_id,
            binding.definition_token_a_id,
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
    // The recorded supply rises only when this program mints the same LP and falls only when it
    // burns the same LP here; a holder burning LP directly only lowers what is outstanding.
    let liquidity_pool_supply = pool
        .liquidity_pool_supply
        .checked_sub(binding.remove_liquidity_amount)
        .expect("Removal burns more LP than the pool's supply");

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

    ShardData::from(&PoolDefinition {
        liquidity_pool_supply,
        reserve_a: pool.reserve_a - withdraw_amount_a,
        reserve_b: pool.reserve_b - withdraw_amount_b,
        active: liquidity_pool_supply != 0,
        ..pool
    })
}
