//! The AMM Program implementation.

#![expect(clippy::arithmetic_side_effects, reason = "TODO: Fix later")]

use std::num::NonZero;

use add::AddBinding;
pub use amm_core as core;
use amm_core::{Instruction, PoolDefinition};
use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, ProgramShardSelector, ShardData},
    program::{AccountMeta, ChainedCall, InstructionData, Plan, ProgramInput, ResolveInput},
};
use remove::RemoveBinding;
use swap::SwapBinding;
use token_core::{TokenDescriptor, TokenKind};

pub mod add;
pub mod new_definition;
pub mod remove;
pub mod swap;

#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    InitializePool {
        pool_is_empty: bool,
        definition: PoolDefinition,
    },
    AddLiquidity(AddBinding),
    RemoveLiquidity(RemoveBinding),
    SwapExactInput(SwapBinding),
    SwapExactOutput(SwapBinding),
    VaultCovers {
        token_program_id: AccountId,
        minimum: u128,
    },
    LiquidityHoldingIsBounded {
        token_program_id: AccountId,
        definition_id: AccountId,
        maximum: u128,
    },
    HoldingIsDefinedBy {
        token_program_id: AccountId,
        definition_id: AccountId,
    },
}

#[must_use]
pub fn transfer_call(
    token_program_id: AccountId,
    from: &AccountMeta,
    to: &AccountMeta,
    definition_id: AccountId,
    amount: u128,
) -> ChainedCall {
    ChainedCall::new(
        token_program_id,
        vec![
            ProgramShardSelector::from(from),
            ProgramShardSelector::from(to),
        ],
        &token_core::Instruction::Transfer {
            amount_to_transfer: amount,
            descriptor: TokenDescriptor {
                definition_id,
                kind: TokenKind::Fungible,
            },
        },
    )
}

pub fn execute(input: ProgramInput<Instruction>, instruction_data: InstructionData) -> Plan {
    let mut plan = Plan::new(&input, instruction_data);
    let ProgramInput {
        self_account_id,
        caller_account_id: _,
        accounts,
        instruction,
    } = input;

    match instruction {
        Instruction::NewDefinition {
            token_a_amount,
            token_b_amount,
            token_program_id,
            definition_token_a_id,
            definition_token_b_id,
            pool_is_empty,
        } => {
            let accounts: [AccountMeta; 7] = accounts
                .try_into()
                .expect("NewDefinition instruction requires exactly seven accounts");
            new_definition::new_definition(
                &mut plan,
                &accounts,
                self_account_id,
                NonZero::new(token_a_amount).expect("Token A should have a nonzero amount"),
                NonZero::new(token_b_amount).expect("Token B should have a nonzero amount"),
                token_program_id,
                definition_token_a_id,
                definition_token_b_id,
                pool_is_empty,
            );
        }
        Instruction::AddLiquidity {
            min_amount_liquidity,
            max_amount_to_add_token_a,
            max_amount_to_add_token_b,
            token_program_id,
            definition_token_a_id,
            definition_token_b_id,
            amount_to_add_token_a,
            amount_to_add_token_b,
            amount_liquidity,
            reserve_bound_a,
            reserve_bound_b,
        } => {
            let accounts: [AccountMeta; 7] = accounts
                .try_into()
                .expect("AddLiquidity instruction requires exactly seven accounts");
            let [_, vault_a, vault_b, pool_definition_lp, ..] = &accounts;
            add::add_liquidity(
                &mut plan,
                &accounts,
                NonZero::new(min_amount_liquidity)
                    .expect("Min amount of liquidity should be nonzero"),
                AddBinding {
                    token_program_id,
                    vault_a_id: vault_a.account_id,
                    vault_b_id: vault_b.account_id,
                    liquidity_pool_id: pool_definition_lp.account_id,
                    definition_token_a_id,
                    definition_token_b_id,
                    max_amount_to_add_token_a,
                    max_amount_to_add_token_b,
                    amount_to_add_token_a,
                    amount_to_add_token_b,
                    amount_liquidity,
                    reserve_bound_a,
                    reserve_bound_b,
                },
            );
        }
        Instruction::RemoveLiquidity {
            remove_liquidity_amount,
            min_amount_to_remove_token_a,
            min_amount_to_remove_token_b,
            token_program_id,
            definition_token_a_id,
            definition_token_b_id,
            amount_to_remove_token_a,
            amount_to_remove_token_b,
            amount_liquidity_burned,
            liquidity_supply_bound,
        } => {
            let accounts: [AccountMeta; 7] = accounts
                .try_into()
                .expect("RemoveLiquidity instruction requires exactly seven accounts");
            let [_, vault_a, vault_b, pool_definition_lp, ..] = &accounts;
            remove::remove_liquidity(
                &mut plan,
                &accounts,
                min_amount_to_remove_token_a,
                min_amount_to_remove_token_b,
                RemoveBinding {
                    token_program_id,
                    vault_a_id: vault_a.account_id,
                    vault_b_id: vault_b.account_id,
                    liquidity_pool_id: pool_definition_lp.account_id,
                    definition_token_a_id,
                    definition_token_b_id,
                    remove_liquidity_amount,
                    amount_to_remove_token_a,
                    amount_to_remove_token_b,
                    amount_liquidity_burned,
                    liquidity_supply_bound,
                },
            );
        }
        Instruction::SwapExactInput {
            swap_amount_in,
            min_amount_out,
            token_definition_id_in,
            token_program_id,
            token_definition_id_out,
            input_is_token_a,
            amount_out,
            reserve_bound_a,
            reserve_bound_b,
        } => {
            let accounts: [AccountMeta; 5] = accounts
                .try_into()
                .expect("SwapExactInput instruction requires exactly five accounts");
            let [_, vault_a, vault_b, ..] = &accounts;
            swap::swap_exact_input(
                &mut plan,
                &accounts,
                min_amount_out,
                SwapBinding {
                    token_program_id,
                    vault_a_id: vault_a.account_id,
                    vault_b_id: vault_b.account_id,
                    input_is_token_a,
                    definition_id_in: token_definition_id_in,
                    definition_id_out: token_definition_id_out,
                    amount_in: swap_amount_in,
                    amount_out,
                    reserve_bound_a,
                    reserve_bound_b,
                },
            );
        }
        Instruction::SwapExactOutput {
            exact_amount_out,
            max_amount_in,
            token_definition_id_in,
            token_program_id,
            token_definition_id_out,
            input_is_token_a,
            amount_in,
            reserve_bound_a,
            reserve_bound_b,
        } => {
            let accounts: [AccountMeta; 5] = accounts
                .try_into()
                .expect("SwapExactOutput instruction requires exactly five accounts");
            let [_, vault_a, vault_b, ..] = &accounts;
            swap::swap_exact_output(
                &mut plan,
                &accounts,
                max_amount_in,
                SwapBinding {
                    token_program_id,
                    vault_a_id: vault_a.account_id,
                    vault_b_id: vault_b.account_id,
                    input_is_token_a,
                    definition_id_in: token_definition_id_in,
                    definition_id_out: token_definition_id_out,
                    amount_in,
                    amount_out: exact_amount_out,
                    reserve_bound_a,
                    reserve_bound_b,
                },
            );
        }
    }

    plan
}

#[must_use]
pub fn resolve(input: &ResolveInput) -> Option<ShardData> {
    let effect =
        Effect::try_from_slice(&input.effect_data).expect("The AMM Program wrote its own effect");

    match effect {
        Effect::InitializePool {
            pool_is_empty,
            definition,
        } => Some(new_definition::initialize_pool(
            pool_shard(input),
            pool_is_empty,
            &definition,
        )),
        Effect::AddLiquidity(binding) => Some(add::pool_after_add(pool_shard(input), &binding)),
        Effect::RemoveLiquidity(binding) => {
            Some(remove::pool_after_remove(pool_shard(input), &binding))
        }
        Effect::SwapExactInput(binding) => {
            Some(swap::pool_after_exact_input(pool_shard(input), &binding))
        }
        Effect::SwapExactOutput(binding) => {
            Some(swap::pool_after_exact_output(pool_shard(input), &binding))
        }
        Effect::VaultCovers {
            token_program_id,
            minimum,
        } => {
            swap::vault_covers(token_shard(input, token_program_id), minimum);
            None
        }
        Effect::LiquidityHoldingIsBounded {
            token_program_id,
            definition_id,
            maximum,
        } => {
            remove::liquidity_holding_is_bounded(
                token_shard(input, token_program_id),
                definition_id,
                maximum,
            );
            None
        }
        Effect::HoldingIsDefinedBy {
            token_program_id,
            definition_id,
        } => {
            new_definition::holding_is_defined_by(
                token_shard(input, token_program_id),
                definition_id,
            );
            None
        }
    }
}

// A handle's shard program is chosen by the transaction, not derived, and `validate_resolution`
// rejects only foreign-shard *writes* — a foreign-shard `Keep` is legal. Every guard here ends in
// `Keep`, so unpinned it could be aimed at a shard the caller fills itself. These are the only
// paths to `pre_data`, so naming the program whose encoding is parsed is unavoidable. Note the
// token guards cannot reuse the pool's `== self_account_id` rule: they inspect the *pool's* token
// program from the AMM, so a self-shaped assert would look right and admit an attacker's shard.
fn pool_shard(input: &ResolveInput) -> &ShardData {
    assert_eq!(
        input.selector.program_account_id, input.self_account_id,
        "The AMM Program resolves pool effects on its own shard"
    );
    &input.pre_data
}

fn token_shard(input: &ResolveInput, token_program_id: AccountId) -> &ShardData {
    assert_eq!(
        input.selector.program_account_id, token_program_id,
        "The AMM Program inspects token holdings on the pool's token program shard"
    );
    &input.pre_data
}
