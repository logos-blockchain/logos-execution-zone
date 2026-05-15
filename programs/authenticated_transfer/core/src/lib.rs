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
}
