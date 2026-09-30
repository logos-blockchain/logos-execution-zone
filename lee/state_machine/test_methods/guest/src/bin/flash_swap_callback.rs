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
//! # Note on `caller_account_id`
//!
//! This program does not enforce any access control on `caller_account_id`.
//! It is designed to be called by the flash swap initiator but could in principle be
//! called by any program. In production, a callback would typically verify the caller
//! if it needs to trust the context it is called from.

use lee_core::{
    native_token::custody_transfer,
    program::{PdaSeed, Plan, ProgramCall, read_program_call},
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct CallbackInstruction {
    /// If true, return the borrowed funds to the vault (happy path).
    /// If false, keep the funds (simulates a malicious callback, triggers rollback).
    pub return_funds: bool,
    pub amount: u128,
}

fn main() {
    let ProgramCall::Plan(input, instruction) = read_program_call::<CallbackInstruction>() else {
        panic!("flash_swap_callback emits no effect to apply")
    };

    // accounts[0] = vault, accounts[1] = receiver
    let Ok([vault, receiver]) = <[_; 2]>::try_from(input.accounts.clone()) else {
        panic!("Callback requires exactly 2 accounts: vault, receiver");
    };

    // The callback itself makes no direct state changes, so it emits no effect of its own.
    let mut plan = Plan::new(&input);
    if instruction.return_funds {
        // Happy path: return the borrowed funds via a token transfer (receiver → vault).
        // The receiver is a PDA of this callback program (seed = [1_u8; 32]).
        plan.call(custody_transfer(
            receiver.account_id,
            PdaSeed::new([1; 32]),
            vault.account_id,
            instruction.amount,
        ));
    }
    // Malicious path (return_funds = false): emit no chained calls.
    // The vault balance will not be restored, so the invariant check in the initiator
    // will panic, rolling back the entire transaction including the initial transfer out.
    plan.write()
}
