use borsh::{BorshDeserialize, BorshSerialize};

use crate::{account::AccountId, program::ProgramId};

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
    },
    UpdateHeader {
        first_segment: AccountId,
        immutable: bool,
    },
    /// Creates a header as [`Message::CreateHeader`] does, but fails unless the chain's image ID
    /// is `image_id`.
    CreateHeaderOf {
        first_segment: AccountId,
        image_id: ProgramId,
        immutable: bool,
    },
    /// Fails unless the target holds a mutable header. Changes nothing.
    AssertMutable,
}
