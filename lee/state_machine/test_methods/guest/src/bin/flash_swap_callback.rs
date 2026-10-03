//! Flash swap callback, the user logic step in the "prep → callback → assert" pattern.
//!
//! # Role
//!
//! This program receives the second of the initiator's three sends:
//! 1. Token transfer out (vault → receiver)
//! 2. **This callback** (user logic)
//! 3. Invariant check (assert vault balance restored)
//!
//! In a real flash swap, this would contain the user's arbitrage or other logic.
//! In this test program, it is controlled by `return_funds`:
//!
//! - `return_funds = true`: sends a token transfer (receiver → vault) to return the funds. The
//!   invariant check will pass and the transaction will succeed.
//!
//! - `return_funds = false`: sends nothing. Funds stay with the receiver. The invariant check will
//!   fail (vault balance < initial), causing full atomic rollback. This simulates a malicious or
//!   buggy callback that does not repay the flash loan.
//!
//! # Note on `origin`
//!
//! This program does not enforce any access control on `origin`.
//! It is designed to be called by the flash swap initiator but could in principle be
//! called by any program. In production, a callback would typically verify the sender
//! if it needs to trust the context it is called from.

use lee_core::{
    account::AccountId,
    native_token::custody_transfer,
    program::{PdaSeed, ReceiveInput, Response, SendMode, run_actor},
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct CallbackMessage {
    pub return_funds: bool,
    pub amount: u128,
    pub vault: AccountId,
    pub receiver: AccountId,
}

fn main() {
    run_actor(|_input: &ReceiveInput, message: CallbackMessage| {
        if message.return_funds {
            Response::keep_state().send(custody_transfer(
                message.receiver,
                PdaSeed::new([1; 32]),
                message.vault,
                message.amount,
                SendMode::Call,
            ))
        } else {
            Response::keep_state()
        }
    })
}
