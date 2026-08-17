//! The AMM Program implementation.

#![expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "TODO: Fix later"
)]

pub use amm_core as core;

use std::convert::Infallible;

use lee_core::{
    account::{Account, AccountDiff, AccountId, BalanceDiff, Data},
    program::AccountDiffOutput,
};

pub mod add;
pub mod new_definition;
pub mod remove;
pub mod swap;

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

/// Every data write in this program (always the pool account) replaces its data wholesale with
/// an already-fully-computed `PoolDefinition` encoding, so `diff_data` already *is* the new data
/// verbatim — materializing it is a passthrough.
pub fn update_from_diff(_pre_state: Account, diff_data: Vec<u8>) -> Result<Data, Infallible> {
    Ok(diff_data
        .try_into()
        .expect("diff_data was already validated to fit under DATA_MAX_LENGTH when constructed"))
}
