//! Flash swap initiator, demonstrates the "prep → callback → assert" pattern using ordered sends
//! and a message to itself.
//!
//! # Pattern
//!
//! A flash swap lets a program optimistically transfer tokens out, run arbitrary user
//! logic (the callback), then assert that invariants hold after the callback. The entire
//! sequence is a single atomic transaction: if any step fails, all state changes roll back.
//!
//! # How it works
//!
//! - `Initiate` (external): sends, in order:
//!   1. A custody transfer out of the vault to the receiver, pinned to the proposed vault balance
//!   2. The user callback (arbitrary logic, e.g. arbitrage)
//!   3. `InvariantCheck` to itself
//! - `InvariantCheck` (internal): requires the message to come from this program, then sends a
//!   zero-amount custody transfer that pins the vault balance to its value before the swap.
//!
//! If the callback does not return funds, the pin fails and the whole transaction rolls back.

use lee_core::{
    account::{AccountId, Actor},
    native_token,
    program::{Call, PdaSeed, ReceiveInput, Response, run_actor},
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum FlashSwapMessage {
    Initiate {
        vault: AccountId,
        receiver: AccountId,
        callback: Actor,
        amount_out: u128,
        vault_balance: u128,
        callback_message: Vec<u8>,
    },
    InvariantCheck {
        vault: AccountId,
        receiver: AccountId,
        vault_balance: u128,
    },
}

fn pinned_transfer(vault: AccountId, receiver: AccountId, amount: u128, balance: u128) -> Call {
    Call::new(
        Actor::native_balance(vault),
        &native_token::Message::Transfer {
            to: receiver,
            amount,
            expect_balance: Some(balance),
        },
    )
    .with_pda_seeds(vec![PdaSeed::new([0; 32])])
}

fn main() {
    run_actor(
        |input: &ReceiveInput, message: FlashSwapMessage| match message {
            FlashSwapMessage::Initiate {
                vault,
                receiver,
                callback,
                amount_out,
                vault_balance,
                callback_message,
            } => Response::keep()
                .send(pinned_transfer(vault, receiver, amount_out, vault_balance))
                .send(Call {
                    to: callback,
                    message: callback_message,
                    pda_seeds: Vec::new(),
                })
                .send(Call::new(
                    input.receiver,
                    &FlashSwapMessage::InvariantCheck {
                        vault,
                        receiver,
                        vault_balance,
                    },
                )),
            FlashSwapMessage::InvariantCheck {
                vault,
                receiver,
                vault_balance,
            } => {
                assert!(
                    input.from_own_program(),
                    "InvariantCheck is an internal message: must be sent by flash_swap_initiator"
                );
                Response::keep().send(pinned_transfer(vault, receiver, 0, vault_balance))
            }
        },
    )
}
