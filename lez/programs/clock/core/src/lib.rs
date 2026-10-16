//! Core data structures and constants for the Clock Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{Timestamp, account::AccountId};

pub const CLOCK_PROGRAM_ACCOUNT_ID: AccountId =
    AccountId::new(*b"/LEZ/ClockProgramAccount/0000000");

pub const CLOCK_NAME: [u8; 5] = *b"clock";

/// The message type for the Clock Program. The sequencer ticks the clock as the last transaction
/// of every block, so every other transaction sees the previous block's ID and timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message {
    Tick {
        timestamp: Timestamp,
        block_id: u64,
    },
    /// Read-only: rounds the clock's timestamp down to a multiple of `granularity`, and fails the
    /// transaction unless the **rounded** timestamp is between `at_least` and `at_most`, both
    /// included.
    ///
    /// Example: with a granularity of 60,000 ms (one minute) and the clock at 125,000 ms, the
    /// rounded timestamp is 120,000. `at_least: 60_000, at_most: 180_000` passes, but
    /// `at_least: 125_000, at_most: 180_000` fails: the clock is in range, its rounded timestamp
    /// is not.
    AssertTimestamp {
        /// The rounding step, in milliseconds; must be at least 1.
        ///
        /// A check that passes keeps passing at least until the current step ends, so a bigger
        /// step gives a transaction more time to be included in a block.
        granularity: Timestamp,
        /// The lowest accepted **rounded** timestamp (not the clock's own), in milliseconds.
        at_least: Timestamp,
        /// The highest accepted **rounded** timestamp (not the clock's own), in milliseconds.
        at_most: Timestamp,
    },
    /// Read-only: rounds the clock's block ID down to a multiple of `granularity`, and fails the
    /// transaction unless the **rounded** block ID is between `at_least` and `at_most`, both
    /// included.
    ///
    /// Example: with a granularity of 50 and the clock at block 57, the rounded block ID is 50.
    /// `at_least: 50, at_most: 100` passes, but `at_least: 55, at_most: 100` fails: block 57 is in
    /// range, its rounded block ID is not.
    AssertBlockId {
        /// The rounding step, in blocks; must be at least 1.
        ///
        /// A check that passes keeps passing at least until the current step ends, so a bigger
        /// step gives a transaction more time to be included in a block.
        granularity: u64,
        /// The lowest accepted **rounded** block ID (not the clock's own).
        at_least: u64,
        /// The highest accepted **rounded** block ID (not the clock's own).
        at_most: u64,
    },
}

/// The data stored in the clock account.
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

#[must_use]
pub fn clock_account_id() -> AccountId {
    AccountId::from_builtin_program_name(&CLOCK_NAME)
}
