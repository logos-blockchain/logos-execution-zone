//! Core data structures and constants for the Clock Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    Timestamp,
    account::{AccountId, Actor},
    program::ReceiveInput,
};

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
        /// The rounding step in milliseconds, at least 1; a passing check keeps passing at least
        /// until the step ends.
        granularity: Timestamp,
        /// The lowest accepted **rounded** timestamp, in milliseconds.
        at_least: Timestamp,
        /// The highest accepted **rounded** timestamp, in milliseconds, so the clock may be up to
        /// `granularity - 1` ms past it; use a granularity of 1 for a strict deadline.
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
        /// The rounding step in blocks, at least 1; a passing check keeps passing at least until
        /// the step ends.
        granularity: u64,
        /// The lowest accepted **rounded** block ID.
        at_least: u64,
        /// The highest accepted **rounded** block ID, so the clock may be up to `granularity - 1`
        /// blocks past it; use a granularity of 1 for a strict deadline.
        at_most: u64,
    },
    /// Read-only: rounds the clock's block ID down to a multiple of `granularity`, and sends it
    /// back to the sender as [`Reply::BlockId`]. Only an actor can read the clock: a transaction
    /// that sends this straight to the clock fails.
    ///
    /// Example: with a granularity of 50 and the clock at block 57, the sender receives
    /// `Reply::BlockId(50)`.
    ///
    /// A private transaction that reads the clock stays valid only while the rounded value is the
    /// one it read, so a fine granularity makes it expire quickly.
    ReadBlockId {
        /// The rounding step in blocks, at least 1.
        granularity: u64,
    },
    /// Read-only: rounds the clock's timestamp down to a multiple of `granularity`, and sends it
    /// back to the sender as [`Reply::Timestamp`]. Only an actor can read the clock: a transaction
    /// that sends this straight to the clock fails.
    ///
    /// Example: with a granularity of 60,000 ms (one minute) and the clock at 125,000 ms, the
    /// sender receives `Reply::Timestamp(120_000)`.
    ///
    /// A private transaction that reads the clock stays valid only while the rounded value is the
    /// one it read, so a fine granularity makes it expire quickly.
    ReadTimestamp {
        /// The rounding step in milliseconds, at least 1.
        granularity: Timestamp,
    },
}

/// The messages the Clock Program sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Reply {
    /// The answer to [`Message::ReadBlockId`]: the block ID rounded down to the read's
    /// granularity.
    BlockId(u64),
    /// The answer to [`Message::ReadTimestamp`]: the timestamp in milliseconds rounded down to the
    /// read's granularity.
    Timestamp(Timestamp),
}

impl Reply {
    /// The clock's reply, if the clock sent `input`; check this before decoding your own message.
    ///
    /// # Panics
    ///
    /// If the clock sent `input` and it is not a reply.
    #[must_use]
    pub fn from_input(input: &ReceiveInput) -> Option<Self> {
        let clock = Actor::new(CLOCK_PROGRAM_ACCOUNT_ID, clock_account_id());
        (input.from == Some(clock))
            .then(|| borsh::from_slice(&input.message).expect("The clock sends only replies"))
    }
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

#[cfg(test)]
mod tests {
    use lee_core::account::ActorState;

    use super::*;

    #[test]
    fn only_a_message_from_the_clock_is_a_reply() {
        let clock = Actor::new(CLOCK_PROGRAM_ACCOUNT_ID, clock_account_id());
        let other = Actor::new(AccountId::new([3; 32]), clock_account_id());
        let input = |from| ReceiveInput {
            receiver: Actor::new(AccountId::new([5; 32]), AccountId::new([6; 32])),
            from,
            is_authorized: false,
            pre_state: ActorState::empty(),
            message: borsh::to_vec(&Reply::Timestamp(7)).unwrap(),
        };

        assert_eq!(
            Reply::from_input(&input(Some(clock))),
            Some(Reply::Timestamp(7))
        );
        assert_eq!(Reply::from_input(&input(Some(other))), None);
        assert_eq!(Reply::from_input(&input(None)), None);
    }
}
