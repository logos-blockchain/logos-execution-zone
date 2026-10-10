//! The AMM Program.
//!
//! This program implements a simple AMM that supports multiple AMM pools (a single pool per
//! token pair).
//!
//! AMM program accepts [`Message`] as input, refer to the corresponding documentation
//! for more details.
//!
//! [`Message`]: amm_program::core::Message

lee_core::define_actor_logic!(raw amm_program::handle_message);
