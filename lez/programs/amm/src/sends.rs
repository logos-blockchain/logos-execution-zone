use amm_core::{PoolDefinition, compute_liquidity_token_pda_seed, compute_vault_pda_seed};
use lee_core::{
    account::{AccountId, Actor},
    program::Call,
};
use token_core::TokenDescriptor;

pub const fn token_actor(pool: &PoolDefinition, account_id: AccountId) -> Actor {
    Actor::new(account_id, pool.token_program_id)
}

pub fn lp_send(pool: &PoolDefinition, pool_id: AccountId, message: &token_core::Message) -> Call {
    Call::new(token_actor(pool, pool.liquidity_pool_id), message)
        .with_pda_seeds(vec![compute_liquidity_token_pda_seed(pool_id)])
}

pub fn withdrawal(
    pool: &PoolDefinition,
    pool_id: AccountId,
    vault_id: AccountId,
    definition_id: AccountId,
    to: AccountId,
    amount: u128,
) -> Call {
    transfer(pool, vault_id, to, definition_id, amount)
        .with_pda_seeds(vec![compute_vault_pda_seed(pool_id, definition_id)])
}

pub fn transfer(
    pool: &PoolDefinition,
    from: AccountId,
    to: AccountId,
    definition_id: AccountId,
    amount: u128,
) -> Call {
    Call::new(
        token_actor(pool, from),
        &token_core::Message::Transfer {
            to,
            descriptor: TokenDescriptor::fungible(definition_id),
            amount,
            notify: None,
        },
    )
}
