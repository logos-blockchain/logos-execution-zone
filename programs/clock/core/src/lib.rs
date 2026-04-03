//! Core data structures and constants for the Clock Program.

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::{Timestamp, account::AccountId};

pub const CLOCK_01_PROGRAM_ACCOUNT_ID: AccountId =
    AccountId::new(*b"/LEZ/ClockProgramAccount/0000001");

pub const CLOCK_10_PROGRAM_ACCOUNT_ID: AccountId =
    AccountId::new(*b"/LEZ/ClockProgramAccount/0000010");

pub const CLOCK_50_PROGRAM_ACCOUNT_ID: AccountId =
    AccountId::new(*b"/LEZ/ClockProgramAccount/0000050");

/// All clock program account ID int the order expected by the clock program.
pub const CLOCK_PROGRAM_ACCOUNT_IDS: [AccountId; 3] = [
    CLOCK_01_PROGRAM_ACCOUNT_ID,
    CLOCK_10_PROGRAM_ACCOUNT_ID,
    CLOCK_50_PROGRAM_ACCOUNT_ID,
];

/// The instruction type for the Clock Program. The sequencer passes the current block timestamp.
pub type Instruction = Timestamp;

/// The data stored in a clock account: `[block_id: u64 LE | timestamp: u64 LE]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ClockAccountData {
    pub block_id: u64,
    pub timestamp: Timestamp,
}

impl ClockAccountData {
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        borsh::to_vec(&self).expect("ClockAccountData serialization should not fail")
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        borsh::from_slice(bytes).expect("ClockAccountData deserialization should not fail")
    }
}
