//! Core data structures and constants for the Clock Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    Timestamp,
    account::{AccountId, Actor},
};

pub const CLOCK_PROGRAM_ACCOUNT_ID: AccountId =
    AccountId::new(*b"/LEZ/ClockProgramAccount/0000000");

pub const CLOCK_NAME: [u8; 5] = *b"clock";

/// The message type for the Clock Program. The sequencer ticks the clock as the first transaction
/// of every block, so later transactions read the current block's ID and timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message {
    Tick {
        timestamp: Timestamp,
        block_id: u64,
    },
    /// Read-only: rounds the clock's block ID down to a multiple of `granularity`, and sends it
    /// back to the sender as [`Reply::BlockId`]. Only an actor can read the clock: a transaction
    /// that sends this straight to the clock fails.
    ///
    /// Example: with a granularity of 50 and the clock at block 57, the sender receives
    /// `Reply::BlockId(50)`.
    ///
    /// With granularity 1, a private transaction proved against the parent state reads its exact
    /// block ID and can expire at the next tick. A coarser granularity keeps the reply unchanged
    /// within a bucket, but crossing a bucket boundary invalidates the clock read.
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
    /// With granularity 1, a private transaction proved against the parent state reads its exact
    /// timestamp and can expire at the next tick if the timestamp changes. A coarser granularity
    /// keeps the reply unchanged within a bucket, but crossing a bucket boundary invalidates the
    /// clock read.
    ReadTimestamp {
        /// The rounding step in milliseconds, at least 1.
        granularity: Timestamp,
    },
}

/// The messages the Clock Program sends. A reader needs `actor_entrypoint!(raw ..)`, because the
/// typed entrypoint decodes every message, a reply included, as the reader's own message type.
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
    /// Decodes the reply in `message` without checking who sent it: check that the sender is
    /// [`clock_actor`] first.
    ///
    /// # Panics
    ///
    /// If `message` is not a reply.
    #[must_use]
    pub fn from_message(message: &[u8]) -> Self {
        borsh::from_slice(message).expect("A clock reply must decode")
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

/// The clock's actor, which sends every [`Reply`].
#[must_use]
pub fn clock_actor() -> Actor {
    Actor::new(CLOCK_PROGRAM_ACCOUNT_ID, clock_account_id())
}
