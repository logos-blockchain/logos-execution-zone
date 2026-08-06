//! The Associated Token Account Program implementation.

pub use associated_token_account_core as core;

pub mod burn;
pub mod create;
pub mod transfer;
pub mod transfer_private;

#[cfg(test)]
mod tests;
