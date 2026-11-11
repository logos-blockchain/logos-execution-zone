//! Time-locked transfer program.
//!
//! Transfers only in a block whose timestamp is at or past the deadline in the message, through a
//! validity window. The actor is the payer's account under this program.

use lee_core::{
    Timestamp,
    account::{AccountId, Actor},
    native_token,
    program::{ReceiveInput, Response},
};

lee_core::actor_entrypoint!(handle_message);

fn handle_message(
    input: &ReceiveInput,
    (amount, deadline, receiver): (u128, Timestamp, AccountId),
) -> Response {
    Response::keep_state()
        .timestamp_window(deadline..)
        .send_sync(
            Actor::native_balance(input.receiver.account_id),
            &native_token::Message::Transfer {
                to: receiver,
                amount,
            },
        )
}
