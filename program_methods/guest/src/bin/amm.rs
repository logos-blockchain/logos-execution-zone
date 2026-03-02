//! The AMM Program.
//!
//! This program implements a simple AMM that supports multiple AMM pools (a single pool per
//! token pair).
//!
//! AMM program accepts [`Instruction`] as input, refer to the corresponding documentation
//! for more details.

use std::num::NonZero;

use amm_core::Instruction;
use nssa_core::program::{ProgramInput, read_nssa_inputs, write_nssa_outputs_with_chained_call};

fn main() {
    let (
        ProgramInput {
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
        Instruction::Swap {
            swap_amount_in,
            min_amount_out,
            token_definition_id_in,
        } => {
            let [pool, vault_a, vault_b, user_holding_a, user_holding_b] = pre_states
                .try_into()
                .expect("Transfer instruction requires exactly five accounts");
            amm_program::swap::swap(
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
        Instruction::SyncReserves => {
            let [pool, vault_a, vault_b] = pre_states
                .try_into()
                .expect("Sync reserves instruction requires exactly three accounts");
            amm_program::sync::sync_reserves(pool, vault_a, vault_b)
        }
        Instruction::RecoverSurplus { mode } => {
            let [pool, vault_a, vault_b, to_holding_a, to_holding_b] = pre_states
                .try_into()
                .expect("Recover surplus instruction requires exactly five accounts");
            amm_program::recover::recover_surplus(
                pool,
                vault_a,
                vault_b,
                to_holding_a,
                to_holding_b,
                mode,
            )
        }
    };

    write_nssa_outputs_with_chained_call(
        instruction_words,
        pre_states_clone,
        post_states,
        chained_calls,
    );
}
