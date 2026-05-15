//! Flash swap callback, the user logic step in the "prep → callback → assert" pattern.
//!
//! # Role
//!
//! This program is called as chained call 2 in the flash swap sequence:
//! 1. Token transfer out (vault → receiver)
//! 2. **This callback** (user logic)
//! 3. Invariant check (assert vault balance restored)
//!
//! In a real flash swap, this would contain the user's arbitrage or other logic.
//! In this test program, it is controlled by `return_funds`:
//!
//! - `return_funds = true`: emits a token transfer (receiver → vault) to return the funds. The
//!   invariant check will pass and the transaction will succeed.
//!
//! - `return_funds = false`: emits no transfers. Funds stay with the receiver. The invariant check
//!   will fail (vault balance < initial), causing full atomic rollback. This simulates a malicious
//!   or buggy callback that does not repay the flash loan.
//!
//! # Note on `caller_program_id`
//!
//! This program does not enforce any access control on `caller_program_id`.
//! It is designed to be called by the flash swap initiator but could in principle be
//! called by any program. In production, a callback would typically verify the caller
//! if it needs to trust the context it is called from.

use nssa_core::program::{
    AccountPostState, ChainedCall, PdaSeed, ProgramId, ProgramInput, ProgramOutput,
    read_nssa_inputs,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CallbackInstruction {
    /// If true, return the borrowed funds to the vault (happy path).
    /// If false, keep the funds (simulates a malicious callback, triggers rollback).
    pub return_funds: bool,
    pub token_program_id: ProgramId,
    pub amount: u128,
}

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id, // not enforced in this callback
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_nssa_inputs::<CallbackInstruction>();

    // pre_states[0] = vault (after transfer out), pre_states[1] = receiver (after transfer out)
    let Ok([vault_pre, receiver_pre]) = <[_; 2]>::try_from(pre_states) else {
        panic!("Callback requires exactly 2 accounts: vault, receiver");
    };

    let mut chained_calls = Vec::new();

    if instruction.return_funds {
        // Happy path: return the borrowed funds via a token transfer (receiver → vault).
        // The receiver is a PDA of this callback program (seed = [1_u8; 32]).
        // Mark the receiver as authorized since it will be PDA-authorized in this chained call.
        let mut receiver_authorized = receiver_pre.clone();
        receiver_authorized.is_authorized = true;
        let transfer_instruction =
            risc0_zkvm::serde::to_vec(&authenticated_transfer_core::Instruction::Transfer {
                amount: instruction.amount,
            })
            .expect("transfer instruction serialization");

        chained_calls.push(ChainedCall {
            program_id: instruction.token_program_id,
            pre_states: vec![receiver_authorized, vault_pre.clone()],
            instruction_data: transfer_instruction,
            pda_seeds: vec![PdaSeed::new([1_u8; 32])],
        });
    }
    // Malicious path (return_funds = false): emit no chained calls.
    // The vault balance will not be restored, so the invariant check in the initiator
    // will panic, rolling back the entire transaction including the initial transfer out.

    // The callback itself makes no direct state changes, accounts pass through unchanged.
    // All mutations go through the token program via chained calls.
    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![vault_pre.clone(), receiver_pre.clone()],
        vec![
            AccountPostState::new(vault_pre.account),
            AccountPostState::new(receiver_pre.account),
        ],
    )
    .with_chained_calls(chained_calls)
    .write();
}
