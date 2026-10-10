//! `system_upgrader`: upgrades the system programs, each one of its PDAs
//! (`PdaSeed::for_system_program(name)`). Pending upgrades live in its registry. Only the block
//! producer includes its transactions.

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{SYSTEM_UPGRADER_ACCOUNT_ID, SystemProgramName};
use lee_core::{BlockId, account::AccountId, program::PdaSeed};

const REGISTRY_SEED: [u8; 32] = *b"/LEZ/v0.3/SystemRegistry/0000000";

/// Top level only. Accounts are listed with the shard each selects. Variants are append-only.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Schedules `name` to switch to the chain at `first_segment` from block `from_height`.
    ///
    /// Accounts: the registry (this program's shard), the system program (the program loader's
    /// shard, a mutable header).
    Schedule {
        name: SystemProgramName,
        first_segment: AccountId,
        from_height: BlockId,
    },
    /// Applies `name`'s pending upgrade, from its height, and clears it.
    ///
    /// Accounts: the registry, the system program (the program loader's shard), then the new
    /// chain in link order.
    Apply {
        name: SystemProgramName,
        from_height: BlockId,
    },
    /// Clears `name`'s pending upgrade, at any height, if it is exactly this one.
    ///
    /// Accounts: the registry.
    Cancel {
        name: SystemProgramName,
        first_segment: AccountId,
        from_height: BlockId,
    },
}

/// A pending upgrade, stored in the [`Registry`] under the system program's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ScheduledUpgrade {
    pub first_segment: AccountId,
    pub from_height: BlockId,
}

/// Every upgradable system program, by name, with its pending upgrade, if any. Stored at
/// [`registry_account_id`]: seeded at genesis.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Registry {
    pub programs: BTreeMap<SystemProgramName, Option<ScheduledUpgrade>>,
}

impl Registry {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("a registry serializes")
    }

    /// An empty registry for an empty shard.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return Some(Self::default());
        }
        borsh::from_slice(bytes).ok()
    }

    /// `name`'s pending upgrade; `None` if nothing is pending or `name` isn't registered.
    #[must_use]
    pub fn scheduled(&self, name: &SystemProgramName) -> Option<ScheduledUpgrade> {
        self.programs.get(name).copied().flatten()
    }
}

/// Where the [`Registry`] lives: a PDA of `system_upgrader`.
#[must_use]
pub fn registry_account_id() -> AccountId {
    AccountId::for_public_pda(&SYSTEM_UPGRADER_ACCOUNT_ID, &PdaSeed::new(REGISTRY_SEED))
}

/// `system_upgrader`'s fixed address.
#[must_use]
pub const fn system_upgrader_account_id() -> AccountId {
    SYSTEM_UPGRADER_ACCOUNT_ID
}
