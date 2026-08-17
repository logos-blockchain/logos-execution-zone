//! The Associated Token Account Program implementation.

pub use associated_token_account_core as core;

use lee_core::{
    account::{AccountDiff, AccountId, BalanceDiff},
    program::AccountDiffOutput,
};

pub mod burn;
pub mod create;
pub mod transfer;

#[cfg(test)]
mod tests;

/// A diff that leaves the account exactly as it was.
#[must_use]
pub fn unchanged(account_id: AccountId) -> AccountDiffOutput {
    AccountDiffOutput::new(AccountDiff {
        id: account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    })
}
