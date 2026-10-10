//! The Token Program.
//!
//! This program implements a simple token system supporting both fungible and non-fungible tokens
//! (NFTs).
//!
//! Token program accepts [`Message`] as input, refer to the corresponding documentation
//! for more details.
//!
//! [`Message`]: token_program::core::Message

lee_core::define_actor_logic!(token_program::handle_message);
