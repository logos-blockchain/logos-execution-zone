use std::num::NonZeroU128;

use amm_core::{
    PoolDefinition, compute_liquidity_token_pda, compute_liquidity_token_pda_seed,
    compute_pool_pda, compute_vault_id,
};
use lee_core::{
    account::{AccountId, BalanceDiff, ProgramShardSelector, ShardData},
    program::{AccountInput, AccountStateDiff, ChainedCall},
};
use token_core::HoldingTarget;

#[expect(clippy::too_many_arguments, reason = "TODO: Fix later")]
#[must_use]
pub fn new_definition(
    pool: &AccountInput,
    vault_a: &AccountInput,
    vault_b: &AccountInput,
    pool_definition_lp: &AccountInput,
    user_holding_a: &AccountInput,
    user_holding_b: &AccountInput,
    user_holding_lp: &AccountInput,
    user_owner: &AccountInput,
    token_a_amount: NonZeroU128,
    token_b_amount: NonZeroU128,
    self_account_id: AccountId,
    token_program_id: AccountId,
    user: &HoldingTarget,
) -> (Vec<AccountStateDiff>, Vec<ChainedCall>) {
    // Verify token_a and token_b are different
    let definition_token_a_id =
        token_core::TokenHolding::try_from(user_holding_a.shard_of(token_program_id))
            .expect("New definition: AMM Program expects valid Token Holding account for Token A")
            .definition_id();
    let definition_token_b_id =
        token_core::TokenHolding::try_from(user_holding_b.shard_of(token_program_id))
            .expect("New definition: AMM Program expects valid Token Holding account for Token B")
            .definition_id();

    assert!(
        definition_token_a_id != definition_token_b_id,
        "Cannot set up a swap for a token with itself"
    );
    assert_eq!(
        user_owner.account_id, user.owner_id,
        "User owner was not provided"
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
        compute_vault_id(token_program_id, pool.account_id, definition_token_a_id),
        "Vault ID does not match PDA"
    );
    assert_eq!(
        vault_b.account_id,
        compute_vault_id(token_program_id, pool.account_id, definition_token_b_id),
        "Vault ID does not match PDA"
    );
    assert_eq!(
        pool_definition_lp.account_id,
        compute_liquidity_token_pda(self_account_id, pool.account_id),
        "Liquidity pool Token Definition Account ID does not match PDA"
    );

    // TODO: return here
    // Verify that Pool Account is not active
    let pool_shard = pool.shard_of(self_account_id);
    let pool_account_data = if pool_shard.is_empty() {
        PoolDefinition::default()
    } else {
        PoolDefinition::try_from(pool_shard).expect("AMM program expects a valid Pool account")
    };

    assert!(
        !pool_account_data.active,
        "Cannot initialize an active Pool Definition"
    );

    // LP Token minting calculation
    let initial_lp = (token_a_amount.get() * token_b_amount.get()).isqrt();

    // Chain call for liquidity token (TokenLP definition -> User LP Holding)
    let instruction = if pool_shard.is_empty() {
        token_core::Instruction::NewFungibleDefinition {
            name: String::from("LP Token"),
            total_supply: initial_lp,
            holder: user.clone(),
        }
    } else {
        token_core::Instruction::Mint {
            holder: user.clone(),
            amount_to_mint: initial_lp,
        }
    };

    // Update pool account
    let pool_post_definition = PoolDefinition {
        token_program_id,
        definition_token_a_id,
        definition_token_b_id,
        vault_a_id: vault_a.account_id,
        vault_b_id: vault_b.account_id,
        liquidity_pool_id: pool_definition_lp.account_id,
        liquidity_pool_supply: initial_lp,
        reserve_a: token_a_amount.into(),
        reserve_b: token_b_amount.into(),
        fees: 0_u128, // TODO: we assume all fees are 0 for now.
        active: true,
    };

    let pool_post = AccountStateDiff::new(
        pool.clone(),
        BalanceDiff::Add(0),
        ShardData::from(&pool_post_definition),
    );

    // Chain call for Token A (user_holding_a -> Vault_A)
    let call_token_a = crate::deposit(
        token_program_id,
        user_holding_a,
        vault_a,
        user,
        pool.account_id,
        token_a_amount.into(),
    );

    // Chain call for Token B (user_holding_b -> Vault_B)
    let call_token_b = crate::deposit(
        token_program_id,
        user_holding_b,
        vault_b,
        user,
        pool.account_id,
        token_b_amount.into(),
    );

    let pool_lp_pda_seed = compute_liquidity_token_pda_seed(pool.account_id);
    let call_token_lp = ChainedCall::new(
        token_program_id,
        vec![
            ProgramShardSelector::from(pool_definition_lp),
            ProgramShardSelector::from(user_holding_lp),
        ],
        &instruction,
    )
    .with_pda_seeds(vec![pool_lp_pda_seed]);

    let chained_calls = vec![call_token_lp, call_token_b, call_token_a];

    let post_diffs = vec![
        pool_post,
        AccountStateDiff::unchanged(vault_a.clone()),
        AccountStateDiff::unchanged(vault_b.clone()),
        AccountStateDiff::unchanged(pool_definition_lp.clone()),
        AccountStateDiff::unchanged(user_holding_a.clone()),
        AccountStateDiff::unchanged(user_holding_b.clone()),
        AccountStateDiff::unchanged(user_holding_lp.clone()),
        AccountStateDiff::unchanged(user_owner.clone()),
    ];

    (post_diffs, chained_calls)
}
