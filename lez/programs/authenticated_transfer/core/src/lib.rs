//! Core data structures for the Authenticated Transfer Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::program::ProgramId;

/// Instruction type for the Authenticated Transfer program.
#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Transfer `amount` of native balance from sender to recipient.
    ///
    /// Required accounts: `[sender, recipient]`.
    /// `recipient_program` names the slot credited at the recipient; `None` credits the
    /// native slot (this program).
    Transfer {
        amount: u128,
        recipient_program: Option<ProgramId>,
    },
}
