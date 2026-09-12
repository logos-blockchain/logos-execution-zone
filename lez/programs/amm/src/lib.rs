//! The AMM Program implementation.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "TODO: Fix later"
)]

pub use amm_core as core;
use amm_core::{PoolDefinition, compute_pool_pda_seed, vault_holder};
use lee_core::{
    account::{AccountId, AccountIdData, ProgramShardSelector},
    program::{AccountInput, ChainedCall, PdaSeed},
};
use token_core::HoldingTarget;

pub mod add;
pub mod new_definition;
pub mod remove;
pub mod swap;

#[cfg(test)]
mod tests;

fn token_transfer(
    token_program_id: AccountId,
    from: (&AccountInput, &HoldingTarget),
    to: (&AccountInput, &HoldingTarget),
    amount: u128,
) -> ChainedCall {
    ChainedCall::new(
        token_program_id,
        vec![
            ProgramShardSelector::from(from.0),
            ProgramShardSelector::from(to.0),
            ProgramShardSelector::balance(from.1.owner_id),
        ],
        &token_core::Instruction::Transfer {
            sender: from.1.clone(),
            recipient: to.1.clone(),
            amount_to_transfer: amount,
        },
    )
}

#[must_use]
pub(crate) fn deposit(
    token_program_id: AccountId,
    user_holding: &AccountInput,
    vault: &AccountInput,
    user: &HoldingTarget,
    pool_id: AccountId,
    amount: u128,
) -> ChainedCall {
    token_transfer(
        token_program_id,
        (user_holding, user),
        (vault, &vault_holder(pool_id)),
        amount,
    )
}

#[must_use]
pub(crate) fn withdraw(
    token_program_id: AccountId,
    vault: &AccountInput,
    user_holding: &AccountInput,
    user: &HoldingTarget,
    pool_id: AccountId,
    pool_seed: PdaSeed,
    amount: u128,
) -> ChainedCall {
    token_transfer(
        token_program_id,
        (vault, &vault_holder(pool_id)),
        (user_holding, user),
        amount,
    )
    .with_pda_seeds(vec![pool_seed])
}

#[must_use]
pub(crate) fn pool_seed(
    pool: &AccountInput,
    definition: &PoolDefinition,
    self_account_id: AccountId,
) -> PdaSeed {
    let seed = compute_pool_pda_seed(
        definition.definition_token_a_id,
        definition.definition_token_b_id,
        definition.token_program_id,
    );
    assert_eq!(
        pool.account_id,
        AccountIdData::public().derive_pda_id(self_account_id, &seed),
        "Pool Definition Account ID does not match PDA"
    );
    seed
}
