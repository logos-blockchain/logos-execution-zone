//! Test-only constructors for otherwise-opaque state types.
//!
//! A [`ValidatedStateDiff`] can normally only be produced by the transaction validation
//! functions, which guarantees it has been checked before any state mutation. These
//! helpers let downstream crates unit-test *post-execution* validation logic — e.g. the
//! system-account and bridge guards in `common` — against a hand-built diff, without
//! running a program in the zkVM.

use std::collections::HashMap;

use crate::{
    Account, AccountId,
    validated_state_diff::{StateDiff, ValidatedStateDiff},
};

/// Builds a [`ValidatedStateDiff`] carrying only the given public-account changes.
#[must_use]
pub const fn validated_state_diff_from_public_diff(
    public_diff: HashMap<AccountId, Account>,
) -> ValidatedStateDiff {
    ValidatedStateDiff::new_unchecked(StateDiff {
        signer_account_ids: Vec::new(),
        public_diff,
        new_commitments: Vec::new(),
        new_nullifiers: Vec::new(),
        program: None,
    })
}
