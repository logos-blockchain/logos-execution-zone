use std::num::NonZeroU128;

use amm_core::{
    PoolDefinition, compute_liquidity_token_pda, compute_liquidity_token_pda_seed,
    compute_pool_pda, compute_vault_pda,
};
use lee_core::{
    account::{AccountId, ProgramShardSelector, ShardData},
    program::{AccountMeta, ChainedCall, Plan},
};

use crate::{Effect, transfer_call};

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
pub fn new_definition(
    plan: &mut Plan,
    accounts: &[AccountMeta; 7],
    self_account_id: AccountId,
    token_a_amount: NonZeroU128,
    token_b_amount: NonZeroU128,
    token_program_id: AccountId,
    definition_token_a_id: AccountId,
    definition_token_b_id: AccountId,
    pool_is_empty: bool,
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
        definition_token_a_id != definition_token_b_id,
        "Cannot set up a swap for a token with itself"
    );
    assert_eq!(
        pool.account_id,
        compute_pool_pda(
            self_account_id,
            definition_token_a_id,
            definition_token_b_id,
            token_program_id
        ),
        "Pool Definition Account ID does not match PDA"
    );
    assert_eq!(
        vault_a.account_id,
        compute_vault_pda(self_account_id, pool.account_id, definition_token_a_id),
        "Vault ID does not match PDA"
    );
    assert_eq!(
        vault_b.account_id,
        compute_vault_pda(self_account_id, pool.account_id, definition_token_b_id),
        "Vault ID does not match PDA"
    );
    assert_eq!(
        pool_definition_lp.account_id,
        compute_liquidity_token_pda(self_account_id, pool.account_id),
        "Liquidity pool Token Definition Account ID does not match PDA"
    );

    let initial_lp = (token_a_amount.get() * token_b_amount.get()).isqrt();

    // Whether the pool shard is empty decides between creating the LP definition and minting more
    // of an existing one, so the branch is a proposal the pool's own effect has to confirm.
    plan.effect(
        pool,
        &Effect::InitializePool {
            pool_is_empty,
            definition: PoolDefinition {
                token_program_id,
                definition_token_a_id,
                definition_token_b_id,
                vault_a_id: vault_a.account_id,
                vault_b_id: vault_b.account_id,
                liquidity_pool_id: pool_definition_lp.account_id,
                liquidity_pool_supply: initial_lp,
                reserve_a: token_a_amount.get(),
                reserve_b: token_b_amount.get(),
                fees: 0_u128, // TODO: we assume all fees are 0 for now.
                active: true,
            },
        },
    );

    let instruction = if pool_is_empty {
        token_core::Instruction::NewFungibleDefinition {
            name: String::from("LP Token"),
            total_supply: initial_lp,
        }
    } else {
        token_core::Instruction::Mint {
            amount_to_mint: initial_lp,
        }
    };

    plan.call(
        ChainedCall::new(
            token_program_id,
            vec![
                ProgramShardSelector::from(pool_definition_lp),
                ProgramShardSelector::from(user_holding_lp),
            ],
            &instruction,
        )
        .with_pda_seeds(vec![compute_liquidity_token_pda_seed(pool.account_id)]),
    );
    // The pool records these two definitions as the tokens it holds; the funding transfers refuse
    // a holding of any other definition.
    plan.call(transfer_call(
        token_program_id,
        user_holding_b,
        vault_b,
        definition_token_b_id,
        token_b_amount.get(),
    ));
    plan.call(transfer_call(
        token_program_id,
        user_holding_a,
        vault_a,
        definition_token_a_id,
        token_a_amount.get(),
    ));
}

#[must_use]
pub fn initialize_pool(
    pre_data: &ShardData,
    pool_is_empty: bool,
    definition: &PoolDefinition,
) -> ShardData {
    assert_eq!(
        pre_data.is_empty(),
        pool_is_empty,
        "Pool emptiness does not match the planned initialization branch"
    );

    if !pool_is_empty {
        let existing =
            PoolDefinition::try_from(pre_data).expect("AMM program expects a valid Pool account");
        assert!(
            !existing.active,
            "Cannot initialize an active Pool Definition"
        );
    }

    ShardData::from(definition)
}
