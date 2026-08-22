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

#[must_use]
pub fn update_from_diff(_pre_state: Account, diff_data: Data) -> Data {
    diff_data
}
