//! The Token Program implementation.

use lee_core::{
    account::AccountId,
    program::{AccountInput, AccountStateDiff},
};
pub use token_core as core;

pub mod burn;
pub mod initialize;
pub mod mint;
pub mod new_definition;
pub mod print_nft;
pub mod transfer;

mod execution_tests;
mod tests;

#[must_use]
pub(crate) fn spend_rows<const N: usize>(
    pre_states: Vec<AccountInput>,
    owner: AccountId,
) -> ([AccountInput; N], Option<AccountInput>) {
    let mut pre_states = pre_states;
    let owner_row = (pre_states.len() > N).then(|| pre_states.pop()).flatten();
    let rows: [AccountInput; N] = pre_states
        .try_into()
        .unwrap_or_else(|_| panic!("Instruction requires exactly {N} data accounts"));
    let owner_input = match (rows.iter().find(|row| row.account_id == owner), &owner_row) {
        (Some(row), None) => row,
        (None, Some(row)) if row.account_id == owner => row,
        _ => panic!("Owner account must be listed exactly once"),
    };
    assert!(owner_input.is_authorized, "Owner authorization is missing");
    (rows, owner_row)
}

#[must_use]
pub(crate) fn with_owner_row(
    diffs: Vec<AccountStateDiff>,
    owner_row: Option<AccountInput>,
) -> Vec<AccountStateDiff> {
    diffs
        .into_iter()
        .chain(owner_row.map(AccountStateDiff::unchanged))
        .collect()
}
