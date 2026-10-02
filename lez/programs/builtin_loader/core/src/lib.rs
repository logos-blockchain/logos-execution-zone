//! `builtin_loader`: schedules and applies upgrades of the system builtins it owns as PDAs.
//!
//! Every builtin lives at `for_public_pda(BUILTIN_LOADER_ACCOUNT_ID, PdaSeed::for_builtin(name))`,
//! so `builtin_loader` updates a builtin's header through ordinary PDA authorization. A pending
//! upgrade is recorded in the builtin's own account, in `builtin_loader`'s shard.

use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::BUILTIN_LOADER_ACCOUNT_ID;
use lee_core::{BlockId, account::AccountId};

/// Variants are append-only.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Schedules builtin `name` to switch to the segment chain starting at `first_segment`, from
    /// block `from_height`. Top level only.
    ///
    /// Required accounts: the builtin's account, `builtin_loader`'s shard (must hold no schedule).
    Schedule {
        name: Vec<u8>,
        first_segment: AccountId,
        from_height: BlockId,
    },
    /// Applies the upgrade scheduled for `name`. Valid only from `from_height`, and only when it
    /// matches the recorded schedule, which it clears.
    ///
    /// Required accounts: the builtin's account (`builtin_loader`'s shard), the builtin's account
    /// (the program loader's shard), then the new segment chain in link order (the program
    /// loader's shard).
    Apply { name: Vec<u8>, from_height: BlockId },
}

/// The pending upgrade stored in a builtin's account, in `builtin_loader`'s shard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ScheduledUpgrade {
    pub first_segment: AccountId,
    pub from_height: BlockId,
}

impl ScheduledUpgrade {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("a scheduled upgrade serializes")
    }

    /// `None` for an empty shard (nothing scheduled) or anything malformed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        borsh::from_slice(bytes).ok()
    }
}

/// `builtin_loader`'s own address: fixed and keyless, the root that owns every builtin.
#[must_use]
pub const fn builtin_loader_account_id() -> AccountId {
    BUILTIN_LOADER_ACCOUNT_ID
}
