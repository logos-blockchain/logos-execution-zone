//! The Token Program implementation.

use lee_core::account::{Account, Data};
pub use token_core as core;

pub mod burn;
pub mod initialize;
pub mod mint;
pub mod new_definition;
pub mod print_nft;
pub mod transfer;

mod tests;

/// Materializes a diff into an account's new data.
///
/// Every data write in this program replaces the account's data wholesale with an
/// already-fully-computed encoding (`TokenDefinition`/`TokenHolding`/`TokenMetadata`), so
/// `diff_data` already *is* the new data verbatim — materializing it is a passthrough.
#[must_use]
pub fn update_from_diff(_pre_state: &Account, diff_data: &[u8]) -> Data {
    diff_data
        .to_vec()
        .try_into()
        .expect("diff_data was already validated to fit under DATA_MAX_LENGTH when constructed")
}
