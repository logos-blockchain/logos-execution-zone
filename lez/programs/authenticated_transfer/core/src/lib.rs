//! Core data structures for the Authenticated Transfer Program.

use serde::{Deserialize, Serialize};

/// Instruction type for the Authenticated Transfer program.
#[derive(Serialize, Deserialize)]
pub enum Instruction {
    /// Transfer `amount` of native balance from sender to recipient.
    ///
    /// Required accounts: `[sender, recipient]`.
    Transfer { amount: u128 },
}
