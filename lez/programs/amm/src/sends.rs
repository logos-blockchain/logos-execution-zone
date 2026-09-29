use amm_core::{Message, PoolDefinition, compute_liquidity_token_pda_seed, compute_vault_pda_seed};
use lee_core::{
    account::{AccountId, Actor},
    program::Envelope,
};
use token_core::{NewTokenDefinition, TokenDescriptor, TokenKind};

pub const fn token_actor(pool: &PoolDefinition, account_id: AccountId) -> Actor {
    Actor::new(account_id, pool.token_program_id)
}

// A liquidity message's sends, exactly as the pool's turn makes them from `pool`'s token program,
// vaults and liquidity definition and the message's exact amounts. A new definition creates the
// liquidity definition when `creates_lp`, and otherwise mints the supply `pool` records.
pub fn liquidity_sends(
    pool_id: AccountId,
    pool: &PoolDefinition,
    message: &Message,
    creates_lp: bool,
) -> Vec<Envelope> {
    let lp_send = |lp_message: &token_core::Message| {
        Envelope::new(token_actor(pool, pool.liquidity_pool_id), lp_message)
            .with_pda_seeds(vec![compute_liquidity_token_pda_seed(pool_id)])
    };
    match *message {
        Message::NewDefinition {
            token_a_amount,
            token_b_amount,
            user_a,
            user_b,
            user_lp,
            ..
        } => vec![
            lp_send(&if creates_lp {
                token_core::Message::NewDefinition {
                    definition: NewTokenDefinition::Fungible {
                        name: String::from("LP Token"),
                        total_supply: pool.liquidity_pool_supply,
                    },
                    holding: user_lp,
                    metadata: None,
                }
            } else {
                token_core::Message::Mint {
                    to: user_lp,
                    amount: pool.liquidity_pool_supply,
                }
            }),
            transfer(
                pool,
                user_b,
                pool.vault_b_id,
                pool.definition_token_b_id,
                token_b_amount,
            ),
            transfer(
                pool,
                user_a,
                pool.vault_a_id,
                pool.definition_token_a_id,
                token_a_amount,
            ),
        ],
        Message::AddLiquidity {
            amount_to_add_token_a,
            amount_to_add_token_b,
            amount_liquidity,
            user_a,
            user_b,
            user_lp,
            ..
        } => vec![
            lp_send(&token_core::Message::Mint {
                to: user_lp,
                amount: amount_liquidity,
            }),
            transfer(
                pool,
                user_b,
                pool.vault_b_id,
                pool.definition_token_b_id,
                amount_to_add_token_b,
            ),
            transfer(
                pool,
                user_a,
                pool.vault_a_id,
                pool.definition_token_a_id,
                amount_to_add_token_a,
            ),
        ],
        Message::RemoveLiquidity {
            remove_liquidity_amount,
            amount_to_remove_token_a,
            amount_to_remove_token_b,
            user_a,
            user_b,
            user_lp,
        } => vec![
            Envelope::new(
                token_actor(pool, user_lp),
                &token_core::Message::Burn {
                    descriptor: fungible(pool.liquidity_pool_id),
                    amount: remove_liquidity_amount,
                    definition: pool.liquidity_pool_id,
                },
            ),
            withdrawal(
                pool,
                pool_id,
                pool.vault_b_id,
                pool.definition_token_b_id,
                user_b,
                amount_to_remove_token_b,
            ),
            withdrawal(
                pool,
                pool_id,
                pool.vault_a_id,
                pool.definition_token_a_id,
                user_a,
                amount_to_remove_token_a,
            ),
        ],
    }
}

pub fn withdrawal(
    pool: &PoolDefinition,
    pool_id: AccountId,
    vault_id: AccountId,
    definition_id: AccountId,
    to: AccountId,
    amount: u128,
) -> Envelope {
    transfer(pool, vault_id, to, definition_id, amount)
        .with_pda_seeds(vec![compute_vault_pda_seed(pool_id, definition_id)])
}

fn transfer(
    pool: &PoolDefinition,
    from: AccountId,
    to: AccountId,
    definition_id: AccountId,
    amount: u128,
) -> Envelope {
    Envelope::new(
        token_actor(pool, from),
        &token_core::Message::Transfer {
            to,
            descriptor: fungible(definition_id),
            amount,
            notify: None,
        },
    )
}

const fn fungible(definition_id: AccountId) -> TokenDescriptor {
    TokenDescriptor {
        definition_id,
        kind: TokenKind::Fungible,
    }
}
