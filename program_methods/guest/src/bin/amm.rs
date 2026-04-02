//! The AMM Program.
//!
//! This program implements a simple AMM that supports multiple AMM pools (a single pool per
//! token pair).
//!
//! AMM program accepts [`Instruction`] as input, refer to the corresponding documentation
//! for more details.

use std::num::NonZero;

use amm_core::Instruction;
use nssa_core::program::{ProgramInput, ProgramOutput, read_nssa_inputs};

fn main() {
    let (
        ProgramInput {
            self_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let pre_states_clone = pre_states.clone();

    let (post_states, chained_calls) = match instruction {
        Instruction::NewDefinition {
            token_a_amount,
            token_b_amount,
            amm_program_id,
        } => {
            let [
                pool,
                vault_a,
                vault_b,
                pool_definition_lp,
                user_holding_a,
                user_holding_b,
                user_holding_lp,
            ] = pre_states
                .try_into()
                .expect("Transfer instruction requires exactly seven accounts");
            amm_program::new_definition::new_definition(
                pool,
                vault_a,
                vault_b,
                pool_definition_lp,
                user_holding_a,
                user_holding_b,
                user_holding_lp,
                NonZero::new(token_a_amount).expect("Token A should have a nonzero amount"),
                NonZero::new(token_b_amount).expect("Token B should have a nonzero amount"),
                amm_program_id,
            )
        }
        Instruction::AddLiquidity {
            min_amount_liquidity,
            max_amount_to_add_token_a,
            max_amount_to_add_token_b,
        } => {
            let [
                pool,
                vault_a,
                vault_b,
                pool_definition_lp,
                user_holding_a,
                user_holding_b,
                user_holding_lp,
            ] = pre_states
                .try_into()
                .expect("Transfer instruction requires exactly seven accounts");
            amm_program::add::add_liquidity(
                pool,
                vault_a,
                vault_b,
                pool_definition_lp,
                user_holding_a,
                user_holding_b,
                user_holding_lp,
                NonZero::new(min_amount_liquidity)
                    .expect("Min amount of liquidity should be nonzero"),
                max_amount_to_add_token_a,
                max_amount_to_add_token_b,
            )
        }
        Instruction::RemoveLiquidity {
            remove_liquidity_amount,
            min_amount_to_remove_token_a,
            min_amount_to_remove_token_b,
        } => {
            let [
                pool,
                vault_a,
                vault_b,
                pool_definition_lp,
                user_holding_a,
                user_holding_b,
                user_holding_lp,
            ] = pre_states
                .try_into()
                .expect("Transfer instruction requires exactly seven accounts");
            amm_program::remove::remove_liquidity(
                pool,
                vault_a,
                vault_b,
                pool_definition_lp,
                user_holding_a,
                user_holding_b,
                user_holding_lp,
                NonZero::new(remove_liquidity_amount)
                    .expect("Remove liquidity amount must be nonzero"),
                min_amount_to_remove_token_a,
                min_amount_to_remove_token_b,
            )
        }
        Instruction::SwapExactInput {
            swap_amount_in,
            min_amount_out,
            token_definition_id_in,
        } => {
            let [pool, vault_a, vault_b, user_holding_a, user_holding_b] = pre_states
                .try_into()
                .expect("SwapExactInput instruction requires exactly five accounts");
            amm_program::swap::swap_exact_input(
                pool,
                vault_a,
                vault_b,
                user_holding_a,
                user_holding_b,
                swap_amount_in,
                min_amount_out,
                token_definition_id_in,
            )
        }
        Instruction::SwapExactOutput {
            exact_amount_out,
            max_amount_in,
            token_definition_id_in,
        } => {
            let [pool, vault_a, vault_b, user_holding_a, user_holding_b] = pre_states
                .try_into()
                .expect("SwapExactOutput instruction requires exactly five accounts");
            amm_program::swap::swap_exact_output(
                pool,
                vault_a,
                vault_b,
                user_holding_a,
                user_holding_b,
                exact_amount_out,
                max_amount_in,
                token_definition_id_in,
            )
        }
    };

    ProgramOutput::new(
        self_program_id,
        instruction_words,
        pre_states_clone,
        post_states,
    )
    .with_chained_calls(chained_calls)
    .write();
}
