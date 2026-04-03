//! Core data structures and constants for the Clock Program.

use nssa_core::{Timestamp, account::AccountId};

pub const CLOCK_01_PROGRAM_ACCOUNT_ID: AccountId =
    AccountId::new(*b"/LEZ/ClockProgramAccount/0000001");

pub const CLOCK_10_PROGRAM_ACCOUNT_ID: AccountId =
    AccountId::new(*b"/LEZ/ClockProgramAccount/0000010");

pub const CLOCK_50_PROGRAM_ACCOUNT_ID: AccountId =
    AccountId::new(*b"/LEZ/ClockProgramAccount/0000050");

/// All clock program account ID in the order expected by the clock program.
pub const CLOCK_PROGRAM_ACCOUNT_IDS: [AccountId; 3] = [
    CLOCK_01_PROGRAM_ACCOUNT_ID,
    CLOCK_10_PROGRAM_ACCOUNT_ID,
    CLOCK_50_PROGRAM_ACCOUNT_ID,
];

/// The instruction type for the Clock Program. The sequencer passes the current block timestamp.
pub type Instruction = Timestamp;

/// The data stored in a clock account: `[block_id: u64 LE | timestamp: u64 LE]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockAccountData {
    pub block_id: u64,
    pub timestamp: Timestamp,
}

impl ClockAccountData {
    #[must_use]
    pub fn to_bytes(self) -> [u8; 16] {
        let mut data = [0_u8; 16];
        data[..8].copy_from_slice(&self.block_id.to_le_bytes());
        data[8..].copy_from_slice(&self.timestamp.to_le_bytes());
        data
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        let block_id = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let timestamp = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        Self {
            block_id,
            timestamp,
        }
    }
}
