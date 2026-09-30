//! The AMM Program.
//!
//! This program implements a simple AMM that supports multiple AMM pools (a single pool per
//! token pair).
//!
//! AMM program accepts [`Instruction`] as input, refer to the corresponding documentation
//! for more details.
//!
//! [`Instruction`]: amm_program::core::Instruction

fn main() {
    lee_core::program::run_program(amm_program::plan, amm_program::apply)
}
