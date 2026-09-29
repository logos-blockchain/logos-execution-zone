//! The Token Program.
//!
//! This program implements a simple token system supporting both fungible and non-fungible tokens
//! (NFTs).
//!
//! Token program accepts [`Message`] as input, refer to the corresponding documentation
//! for more details.
//!
//! [`Message`]: token_program::core::Message

fn main() {
    lee_core::program::run_actor(token_program::receive)
}
