//! The AMM Program implementation.

#![expect(clippy::arithmetic_side_effects, reason = "TODO: Fix later")]

use std::num::NonZero;

use add::AddBinding;
pub use amm_core as core;
use amm_core::{Instruction, PoolDefinition};
use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, ProgramShardSelector, ShardData},
    program::{AccountMeta, ChainedCall, Plan, PlanInput},
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

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    InitializePool {
        pool_is_empty: bool,
        definition: PoolDefinition,
    },
    AddLiquidity(AddBinding),
    RemoveLiquidity(RemoveBinding),
    Swap(SwapBinding),
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

pub fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    let mut plan = Plan::new(input);
    match instruction {
        Instruction::NewDefinition {
            token_a_amount,
            token_b_amount,
            token_program_id,
            definition_token_a_id,
            definition_token_b_id,
            pool_is_empty,
        } => {
            let accounts: &[AccountMeta; 7] = input
                .accounts
                .as_slice()
                .try_into()
                .expect("NewDefinition instruction requires exactly seven accounts");
            new_definition::new_definition(
                &mut plan,
                accounts,
                input.self_account_id,
                NonZero::new(token_a_amount).expect("Token A should have a nonzero amount"),
                NonZero::new(token_b_amount).expect("Token B should have a nonzero amount"),
                token_program_id,
                definition_token_a_id,
                definition_token_b_id,
                pool_is_empty,
            );
        }
        Instruction::AddLiquidity {
            max_amount_to_add_token_a,
            max_amount_to_add_token_b,
            token_program_id,
            definition_token_a_id,
            definition_token_b_id,
            amount_to_add_token_a,
            amount_to_add_token_b,
            amount_liquidity,
        } => {
            let accounts: &[AccountMeta; 7] = input
                .accounts
                .as_slice()
                .try_into()
                .expect("AddLiquidity instruction requires exactly seven accounts");
            let [_, vault_a, vault_b, pool_definition_lp, ..] = accounts;
            add::add_liquidity(
                &mut plan,
                accounts,
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
                },
            );
        }
        Instruction::RemoveLiquidity {
            remove_liquidity_amount,
            token_program_id,
            definition_token_a_id,
            definition_token_b_id,
            amount_to_remove_token_a,
            amount_to_remove_token_b,
        } => {
            let accounts: &[AccountMeta; 7] = input
                .accounts
                .as_slice()
                .try_into()
                .expect("RemoveLiquidity instruction requires exactly seven accounts");
            let [_, vault_a, vault_b, pool_definition_lp, ..] = accounts;
            remove::remove_liquidity(
                &mut plan,
                accounts,
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
                },
            );
        }
        Instruction::Swap {
            token_program_id,
            definition_id_in,
            definition_id_out,
            amount_in,
            amount_out,
        } => {
            let accounts: &[AccountMeta; 5] = input
                .accounts
                .as_slice()
                .try_into()
                .expect("Swap instruction requires exactly five accounts");
            let [_, input_vault, output_vault, ..] = accounts;
            swap::swap(
                &mut plan,
                accounts,
                SwapBinding {
                    token_program_id,
                    input_vault_id: input_vault.account_id,
                    output_vault_id: output_vault.account_id,
                    definition_id_in,
                    definition_id_out,
                    amount_in,
                    amount_out,
                },
            );
        }
    }

    plan
}

#[must_use]
pub fn apply(effect: Effect, pre_data: &ShardData) -> Option<ShardData> {
    Some(match effect {
        Effect::InitializePool {
            pool_is_empty,
            definition,
        } => new_definition::initialize_pool(pre_data, pool_is_empty, &definition),
        Effect::AddLiquidity(binding) => add::pool_after_add(pre_data, &binding),
        Effect::RemoveLiquidity(binding) => remove::pool_after_remove(pre_data, &binding),
        Effect::Swap(binding) => swap::pool_after_swap(pre_data, &binding),
    })
}
