use std::num::NonZeroU128;

use amm_core::{PoolDefinition, compute_liquidity_token_pda_seed};
use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, ProgramShardSelector, ShardData},
    program::{AccountMeta, ChainedCall, Plan, Proposed},
};

use crate::{Effect, transfer_call};

#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AddBinding {
    pub token_program_id: AccountId,
    pub vault_a_id: AccountId,
    pub vault_b_id: AccountId,
    pub liquidity_pool_id: AccountId,
    pub definition_token_a_id: AccountId,
    pub definition_token_b_id: AccountId,
    pub max_amount_to_add_token_a: u128,
    pub max_amount_to_add_token_b: u128,
    pub amount_to_add_token_a: u128,
    pub amount_to_add_token_b: u128,
    pub amount_liquidity: u128,
    pub reserve_bound_a: u128,
    pub reserve_bound_b: u128,
}

// Everything an add sends outside the pool's own shard. Every quantity here is derived from
// reserves the planner cannot read, so the legs are reachable only from a `Checked` copy.
#[derive(Clone, Copy)]
struct Deposit {
    token_program_id: AccountId,
    definition_token_a_id: AccountId,
    definition_token_b_id: AccountId,
    amount_to_add_token_a: u128,
    amount_to_add_token_b: u128,
    amount_liquidity: u128,
    reserve_bound_a: u128,
    reserve_bound_b: u128,
}

impl From<&AddBinding> for Deposit {
    fn from(binding: &AddBinding) -> Self {
        Self {
            token_program_id: binding.token_program_id,
            definition_token_a_id: binding.definition_token_a_id,
            definition_token_b_id: binding.definition_token_b_id,
            amount_to_add_token_a: binding.amount_to_add_token_a,
            amount_to_add_token_b: binding.amount_to_add_token_b,
            amount_liquidity: binding.amount_liquidity,
            reserve_bound_a: binding.reserve_bound_a,
            reserve_bound_b: binding.reserve_bound_b,
        }
    }
}

pub fn add_liquidity(
    plan: &mut Plan,
    accounts: &[AccountMeta; 7],
    min_amount_liquidity: NonZeroU128,
    binding: AddBinding,
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

    let max_amount_to_add_token_a = binding.max_amount_to_add_token_a;
    let max_amount_to_add_token_b = binding.max_amount_to_add_token_b;
    assert!(
        max_amount_to_add_token_a != 0 && max_amount_to_add_token_b != 0,
        "Both max-balances must be nonzero"
    );

    let proposal = Proposed::new(Deposit::from(&binding));
    let deposit = plan
        .require(pool, &Effect::AddLiquidity(binding), proposal)
        .get();

    plan.effect(
        vault_a,
        &Effect::VaultCovers {
            token_program_id: deposit.token_program_id,
            minimum: deposit.reserve_bound_a,
        },
    );
    plan.effect(
        vault_b,
        &Effect::VaultCovers {
            token_program_id: deposit.token_program_id,
            minimum: deposit.reserve_bound_b,
        },
    );

    assert!(
        max_amount_to_add_token_a >= deposit.amount_to_add_token_a,
        "Actual trade amounts cannot exceed max_amounts"
    );
    assert!(
        max_amount_to_add_token_b >= deposit.amount_to_add_token_b,
        "Actual trade amounts cannot exceed max_amounts"
    );
    assert!(deposit.amount_to_add_token_a != 0, "A trade amount is 0");
    assert!(deposit.amount_to_add_token_b != 0, "A trade amount is 0");
    assert!(deposit.amount_liquidity != 0, "Payable LP must be nonzero");
    assert!(
        deposit.amount_liquidity >= min_amount_liquidity.get(),
        "Payable LP is less than provided minimum LP amount"
    );

    plan.call(
        ChainedCall::new(
            deposit.token_program_id,
            vec![
                ProgramShardSelector::from(pool_definition_lp),
                ProgramShardSelector::from(user_holding_lp),
            ],
            &token_core::Instruction::Mint {
                amount_to_mint: deposit.amount_liquidity,
            },
        )
        .with_pda_seeds(vec![compute_liquidity_token_pda_seed(pool.account_id)]),
    );
    plan.call(transfer_call(
        deposit.token_program_id,
        user_holding_b,
        vault_b,
        deposit.definition_token_b_id,
        deposit.amount_to_add_token_b,
    ));
    plan.call(transfer_call(
        deposit.token_program_id,
        user_holding_a,
        vault_a,
        deposit.definition_token_a_id,
        deposit.amount_to_add_token_a,
    ));
}

#[must_use]
pub fn pool_after_add(pre_data: &ShardData, binding: &AddBinding) -> ShardData {
    let pool = PoolDefinition::try_from(pre_data)
        .expect("Add liquidity: AMM Program expects valid Pool Definition Account");

    assert_eq!(
        pool.token_program_id, binding.token_program_id,
        "Add liquidity routes through a token program the pool does not use"
    );
    assert_eq!(
        binding.vault_a_id, pool.vault_a_id,
        "Vault A was not provided"
    );
    assert_eq!(
        pool.liquidity_pool_id, binding.liquidity_pool_id,
        "LP definition mismatch"
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

    assert!(pool.reserve_a != 0, "Reserves must be nonzero");
    assert!(pool.reserve_b != 0, "Reserves must be nonzero");
    assert!(
        pool.reserve_a <= binding.reserve_bound_a,
        "Reserve for Token A exceeds the bound the vault was checked against"
    );
    assert!(
        pool.reserve_b <= binding.reserve_bound_b,
        "Reserve for Token B exceeds the bound the vault was checked against"
    );

    let ideal_a = amm_core::ideal_deposit(
        pool.reserve_a,
        pool.reserve_b,
        binding.max_amount_to_add_token_b,
    )
    .expect("reserve * max amount overflows u128");
    let ideal_b = amm_core::ideal_deposit(
        pool.reserve_b,
        pool.reserve_a,
        binding.max_amount_to_add_token_a,
    )
    .expect("reserve * max amount overflows u128");

    let actual_amount_a = if ideal_a > binding.max_amount_to_add_token_a {
        binding.max_amount_to_add_token_a
    } else {
        ideal_a
    };
    let actual_amount_b = if ideal_b > binding.max_amount_to_add_token_b {
        binding.max_amount_to_add_token_b
    } else {
        ideal_b
    };

    assert_eq!(
        actual_amount_a, binding.amount_to_add_token_a,
        "Proposed Token A deposit does not match the pool's ideal amount"
    );
    assert_eq!(
        actual_amount_b, binding.amount_to_add_token_b,
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
        delta_lp, binding.amount_liquidity,
        "Proposed LP amount does not match the pool's mint calculation"
    );

    ShardData::from(&PoolDefinition {
        liquidity_pool_supply: pool.liquidity_pool_supply + delta_lp,
        reserve_a: pool.reserve_a + actual_amount_a,
        reserve_b: pool.reserve_b + actual_amount_b,
        ..pool
    })
}
