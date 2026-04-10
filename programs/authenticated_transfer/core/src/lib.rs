//! Core data structures for the Authenticated Transfer Program.

use serde::{Deserialize, Serialize};

/// Instruction type for the Authenticated Transfer program.
#[derive(Serialize, Deserialize)]
pub enum Instruction {
    /// Transfer `amount` of native balance from sender to recipient.
    ///
    /// Required accounts: `[sender, recipient]`.
    Transfer { amount: u128 },

    /// Initialize a new account under the ownership of this program.
    ///
    /// Required accounts: `[account_to_initialize]`.
    Initialize,

    /// Mint `amount` into a new account at genesis (`block_id` == 0).
    ///
    /// Claims the target account (sets `program_owner` to `authenticated_transfer` program id)
    /// and sets its balance in a single operation.
    ///
    /// Required accounts: `[target_account, clock_account]`.
    ///
    /// Panics if:
    /// - `target_account` is not in the default (uninitialized) state
    /// - clock's `block_id` is not 0
    Mint { amount: u128 },
}
