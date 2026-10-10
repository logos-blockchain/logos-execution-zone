//! The AMM Program implementation.

pub use amm_core as core;
use amm_core::{Message, PoolDefinition};
use lee_core::{
    account::ActorState,
    program::{ReceiveInput, Response},
};
use token_core::{NewTokenDefinition, TokenDescriptor};

use crate::sends::{lp_send, token_actor, transfer, withdrawal};

pub mod add;
pub mod new_definition;
pub mod remove;
mod sends;
pub mod swap;

#[cfg(test)]
mod tests;

pub fn handle_message(input: &ReceiveInput) -> Response {
    if let Ok(pool) = PoolDefinition::try_from(&input.pre_state)
        && input
            .from
            .is_some_and(|from| from.program_account_id == pool.token_program_id)
    {
        let token_core::Message::Notification(notification) =
            borsh::from_slice(&input.message).expect("a token message must decode")
        else {
            panic!("The token program sends the pool only notifications");
        };
        return swap::swap(input, &pool, &notification);
    }

    let message: Message = borsh::from_slice(&input.message).expect("an AMM message must decode");
    let pool_id = input.receiver.account_id;
    match message {
        Message::NewDefinition {
            token_a_amount,
            token_b_amount,
            token_program_id,
            definition_token_a_id,
            definition_token_b_id,
            user_a,
            user_b,
            user_lp,
        } => {
            let (pool, pool_was_empty) = new_definition::new_pool(
                input,
                token_a_amount,
                token_b_amount,
                token_program_id,
                definition_token_a_id,
                definition_token_b_id,
            );
            let lp = if pool_was_empty {
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
            };
            Response::set_state(ActorState::from(&pool))
                .send(lp_send(&pool, pool_id, &lp))
                .send(transfer(
                    &pool,
                    user_b,
                    pool.vault_b_id,
                    pool.definition_token_b_id,
                    token_b_amount,
                ))
                .send(transfer(
                    &pool,
                    user_a,
                    pool.vault_a_id,
                    pool.definition_token_a_id,
                    token_a_amount,
                ))
        }
        Message::AddLiquidity {
            max_amount_to_add_token_a,
            max_amount_to_add_token_b,
            amount_to_add_token_a,
            amount_to_add_token_b,
            amount_liquidity,
            user_a,
            user_b,
            user_lp,
        } => {
            let pool = PoolDefinition::try_from(&input.pre_state)
                .expect("Add liquidity: AMM Program expects valid Pool Definition Account");
            let after = add::pool_after_add(
                &pool,
                max_amount_to_add_token_a,
                max_amount_to_add_token_b,
                amount_to_add_token_a,
                amount_to_add_token_b,
                amount_liquidity,
            );
            Response::set_state(ActorState::from(&after))
                .send(lp_send(
                    &pool,
                    pool_id,
                    &token_core::Message::Mint {
                        to: user_lp,
                        amount: amount_liquidity,
                    },
                ))
                .send(transfer(
                    &pool,
                    user_b,
                    pool.vault_b_id,
                    pool.definition_token_b_id,
                    amount_to_add_token_b,
                ))
                .send(transfer(
                    &pool,
                    user_a,
                    pool.vault_a_id,
                    pool.definition_token_a_id,
                    amount_to_add_token_a,
                ))
        }
        Message::RemoveLiquidity {
            remove_liquidity_amount,
            amount_to_remove_token_a,
            amount_to_remove_token_b,
            user_a,
            user_b,
            user_lp,
        } => {
            let pool = PoolDefinition::try_from(&input.pre_state)
                .expect("Remove liquidity: AMM Program expects a valid Pool Definition Account");
            let after = remove::pool_after_remove(
                &pool,
                remove_liquidity_amount,
                amount_to_remove_token_a,
                amount_to_remove_token_b,
            );
            Response::set_state(ActorState::from(&after))
                .call(
                    token_actor(&pool, user_lp),
                    &token_core::Message::Burn {
                        descriptor: TokenDescriptor::fungible(pool.liquidity_pool_id),
                        amount: remove_liquidity_amount,
                        definition: pool.liquidity_pool_id,
                    },
                )
                .send(withdrawal(
                    &pool,
                    pool_id,
                    pool.vault_b_id,
                    pool.definition_token_b_id,
                    user_b,
                    amount_to_remove_token_b,
                ))
                .send(withdrawal(
                    &pool,
                    pool_id,
                    pool.vault_a_id,
                    pool.definition_token_a_id,
                    user_a,
                    amount_to_remove_token_a,
                ))
        }
    }
}
