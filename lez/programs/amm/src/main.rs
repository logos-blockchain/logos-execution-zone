//! The AMM Program.
//!
//! This program implements a simple AMM that supports multiple AMM pools (a single pool per
//! token pair).
//!
//! AMM program accepts [`Message`] as input, refer to the corresponding documentation
//! for more details.
//!
//! [`Message`]: amm_program::core::Message

fn main() {
    lee_core::program::run_actor_with(amm_program::receive)
}
