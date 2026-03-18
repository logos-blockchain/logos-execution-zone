//! The AMM Program implementation.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "TODO: Fix later"
)]

pub use amm_core as core;

pub mod add;
pub mod new_definition;
pub mod remove;
pub mod swap;

#[cfg(test)]
mod tests;
