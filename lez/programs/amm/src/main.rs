//! The AMM Program.
//!
//! This program implements a simple AMM that supports multiple AMM pools (a single pool per
//! token pair).
//!
//! AMM program accepts [`Instruction`] as input, refer to the corresponding documentation
//! for more details.

use std::num::NonZero;

use amm_core::Instruction;
use lee_core::program::{
    ProgramCall, ProgramInput, ProgramOutput, read_lee_call, respond_unsupported_call,
};

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let (state_diffs, chained_calls) = match instruction {
        Instruction::NewDefinition {
            token_a_amount,
            token_b_amount,
            token_program_id,
            user,
        } => {
            let [
                pool,
                vault_a,
                vault_b,
                pool_definition_lp,
                user_holding_a,
                user_holding_b,
                user_holding_lp,
                user_owner,
            ] = pre_states
                .try_into()
                .expect("NewDefinition instruction requires exactly eight accounts");
            amm_program::new_definition::new_definition(
                &pool,
                &vault_a,
                &vault_b,
                &pool_definition_lp,
                &user_holding_a,
                &user_holding_b,
                &user_holding_lp,
                &user_owner,
                NonZero::new(token_a_amount).expect("Token A should have a nonzero amount"),
                NonZero::new(token_b_amount).expect("Token B should have a nonzero amount"),
                self_account_id,
                token_program_id,
                &user,
            )
        }
        Instruction::AddLiquidity {
            min_amount_liquidity,
            max_amount_to_add_token_a,
            max_amount_to_add_token_b,
            user,
        } => {
            let [
                pool,
                vault_a,
                vault_b,
                pool_definition_lp,
                user_holding_a,
                user_holding_b,
                user_holding_lp,
                user_owner,
            ] = pre_states
                .try_into()
                .expect("AddLiquidity instruction requires exactly eight accounts");
            amm_program::add::add_liquidity(
                &pool,
                &vault_a,
                &vault_b,
                &pool_definition_lp,
                &user_holding_a,
                &user_holding_b,
                &user_holding_lp,
                &user_owner,
                NonZero::new(min_amount_liquidity)
                    .expect("Min amount of liquidity should be nonzero"),
                max_amount_to_add_token_a,
                max_amount_to_add_token_b,
                self_account_id,
                &user,
            )
        }
        Instruction::RemoveLiquidity {
            remove_liquidity_amount,
            min_amount_to_remove_token_a,
            min_amount_to_remove_token_b,
            user,
        } => {
            let [
                pool,
                vault_a,
                vault_b,
                pool_definition_lp,
                user_holding_a,
                user_holding_b,
                user_holding_lp,
                user_owner,
            ] = pre_states
                .try_into()
                .expect("RemoveLiquidity instruction requires exactly eight accounts");
            amm_program::remove::remove_liquidity(
                &pool,
                &vault_a,
                &vault_b,
                &pool_definition_lp,
                &user_holding_a,
                &user_holding_b,
                &user_holding_lp,
                &user_owner,
                NonZero::new(remove_liquidity_amount)
                    .expect("Remove liquidity amount must be nonzero"),
                min_amount_to_remove_token_a,
                min_amount_to_remove_token_b,
                self_account_id,
                &user,
            )
        }
        Instruction::SwapExactInput {
            swap_amount_in,
            min_amount_out,
            token_definition_id_in,
            user,
        } => {
            let [
                pool,
                vault_a,
                vault_b,
                user_holding_a,
                user_holding_b,
                user_owner,
            ] = pre_states
                .try_into()
                .expect("SwapExactInput instruction requires exactly six accounts");
            amm_program::swap::swap_exact_input(
                pool,
                vault_a,
                vault_b,
                user_holding_a,
                user_holding_b,
                user_owner,
                swap_amount_in,
                min_amount_out,
                token_definition_id_in,
                self_account_id,
                &user,
            )
        }
        Instruction::SwapExactOutput {
            exact_amount_out,
            max_amount_in,
            token_definition_id_in,
            user,
        } => {
            let [
                pool,
                vault_a,
                vault_b,
                user_holding_a,
                user_holding_b,
                user_owner,
            ] = pre_states
                .try_into()
                .expect("SwapExactOutput instruction requires exactly six accounts");
            amm_program::swap::swap_exact_output(
                pool,
                vault_a,
                vault_b,
                user_holding_a,
                user_holding_b,
                user_owner,
                exact_amount_out,
                max_amount_in,
                token_definition_id_in,
                self_account_id,
                &user,
            )
        }
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .with_chained_calls(chained_calls)
    .write();
}
