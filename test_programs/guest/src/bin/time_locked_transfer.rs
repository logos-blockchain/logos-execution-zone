//! Time-locked transfer program.
//!
//! Demonstrates how a program gates on the on-chain timestamp without reading it: the deadline
//! travels in the message and an `AssertTimestamp` send to the clock actor is what compares it
//! against the clock's own timestamp. The transfer only settles when the clock is at or past
//! the deadline; otherwise the assertion panics and the whole transaction rolls back. The actor
//! is the payer's account under this program.

use clock_core::CLOCK_01_PROGRAM_ACCOUNT_ID;
use lee_core::{
    Timestamp,
    account::{AccountId, Actor},
    native_token,
    program::{Call, ReceiveInput, Response, run_actor},
};

fn main() {
    run_actor(receive)
}

fn receive(
    input: &ReceiveInput,
    (amount, deadline, receiver): (u128, Timestamp, AccountId),
) -> Response {
    Response::keep()
        .call(Call::new(
            Actor::new(CLOCK_01_PROGRAM_ACCOUNT_ID, clock_core::clock_account_id()),
            &clock_core::Message::AssertTimestamp {
                at_least: deadline,
                at_most: Timestamp::MAX,
            },
        ))
        .call(Call::new(
            Actor::native_balance(input.receiver.account_id),
            &native_token::Message::Transfer {
                to: receiver,
                amount,
            },
        ))
}
