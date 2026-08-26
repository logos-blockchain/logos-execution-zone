//! Core data structures for the Authenticated Transfer Program.

use borsh::{BorshDeserialize, BorshSerialize};

/// Instruction type for the Authenticated Transfer program.
#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Transfer `amount` of native balance from sender to recipient.
    ///
    /// Required positions: `[sender's native slot, the recipient slot to credit]`. Which slot
    /// is credited is named by the transaction, not by this instruction.
    Transfer { amount: u128 },
}
