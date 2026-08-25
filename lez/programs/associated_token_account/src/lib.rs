//! The Associated Token Account Program implementation.

pub use associated_token_account_core as core;

pub mod burn;
pub mod close;
pub mod create;
pub mod transfer;

#[cfg(test)]
mod tests;
