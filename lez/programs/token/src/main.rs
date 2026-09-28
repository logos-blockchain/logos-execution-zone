//! The Token Program.
//!
//! This program implements a simple token system supporting both fungible and non-fungible tokens
//! (NFTs).
//!
//! Token program accepts [`Instruction`] as input, refer to the corresponding documentation
//! for more details.
//!
//! [`Instruction`]: token_program::core::Instruction

fn main() {
    lee_core::program::run_program(token_program::plan, token_program::apply)
}
