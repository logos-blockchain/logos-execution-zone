//! The AMM Program implementation.

pub use amm_core as core;

pub mod add;
pub mod new_definition;
pub mod recover;
pub mod remove;
pub mod swap;
pub mod sync;

mod vault_utils;

mod tests;
