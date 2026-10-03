//! The AMM Program implementation.

pub use amm_core as core;
use amm_core::{Message, PoolDefinition};
use lee_core::{
    account::ActorState,
    program::{ReceiveInput, Response},
};

use crate::sends::liquidity_sends;

pub mod add;
pub mod new_definition;
pub mod remove;
mod sends;
pub mod swap;

#[cfg(test)]
mod tests;

pub fn receive(input: &ReceiveInput) -> Response {
    if let Ok(pool) = PoolDefinition::try_from(&input.pre_state)
        && input.origin == Some(pool.token_program_id)
    {
        let token_core::Message::Notification(notification) =
            borsh::from_slice(&input.message).expect("a token message must decode")
        else {
            panic!("The token program sends the pool only notifications");
        };
        return swap::swap(input, &pool, &notification);
    }

    let message: Message = borsh::from_slice(&input.message).expect("an AMM message must decode");
    let (pool, after, creates_lp) = match message {
        Message::NewDefinition {
            token_a_amount,
            token_b_amount,
            token_program_id,
            definition_token_a_id,
            definition_token_b_id,
            ..
        } => {
            let (pool, pool_was_empty) = new_definition::new_pool(
                input,
                token_a_amount,
                token_b_amount,
                token_program_id,
                definition_token_a_id,
                definition_token_b_id,
            );
            (pool.clone(), pool, pool_was_empty)
        }
        Message::AddLiquidity {
            max_amount_to_add_token_a,
            max_amount_to_add_token_b,
            amount_to_add_token_a,
            amount_to_add_token_b,
            amount_liquidity,
            ..
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
            (pool, after, false)
        }
        Message::RemoveLiquidity {
            remove_liquidity_amount,
            amount_to_remove_token_a,
            amount_to_remove_token_b,
            ..
        } => {
            let pool = PoolDefinition::try_from(&input.pre_state)
                .expect("Remove liquidity: AMM Program expects a valid Pool Definition Account");
            let after = remove::pool_after_remove(
                &pool,
                remove_liquidity_amount,
                amount_to_remove_token_a,
                amount_to_remove_token_b,
            );
            (pool, after, false)
        }
    };
    Response {
        calls: liquidity_sends(input.receiver.account_id, &pool, &message, creates_lp),
        ..Response::set_state(ActorState::from(&after))
    }
}
