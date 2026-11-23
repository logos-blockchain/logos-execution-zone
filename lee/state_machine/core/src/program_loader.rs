use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    account::{AccountId, Actor},
    program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramId, SyncMessage},
};

pub const MAX_ENV_VAR_LEN: usize = 1024;

/// Variants are append-only. Borsh encodes the variant as a leading tag byte, so inserting one
/// ahead of `WriteSegment` shifts every existing encoding.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message {
    /// Writes a new segment to the target's empty loader actor state; the target must be
    /// authorized.
    ///
    /// If `next_segment` is `Some`, that account must already hold a valid `ProgramSegment`.
    /// Segments are immutable and linked from tail to head.
    WriteSegment {
        bytecode: Vec<u8>,
        next_segment: Option<AccountId>,
    },
    CreateHeader {
        first_segment: AccountId,
        immutable: bool,
        env_var: Vec<u8>,
    },
    UpdateHeader {
        first_segment: AccountId,
        immutable: bool,
        env_var: Vec<u8>,
    },
    /// Creates a header as [`Message::CreateHeader`] does, but fails unless the chain's image ID
    /// is `image_id`.
    CreateHeaderOf {
        first_segment: AccountId,
        image_id: ProgramId,
        immutable: bool,
        env_var: Vec<u8>,
    },
    /// Fails unless the target holds a mutable header. Changes nothing.
    AssertMutable,
    /// Fails unless the target holds a header whose `env_var` is `env_var`. Changes nothing.
    AssertEnvVar { env_var: Vec<u8> },
}

#[must_use]
pub fn assert_env_var(header: AccountId, env_var: Vec<u8>) -> SyncMessage {
    SyncMessage::new(
        Actor::new(header, PROGRAM_LOADER_ACCOUNT_ID),
        &Message::AssertEnvVar { env_var },
    )
}
