//! `system_upgrader`: upgrades and installs the system programs, each one of its PDAs
//! (`PdaSeed::for_system_program(name)`). Pending upgrades live in its registry. Every change but
//! `Apply` must be approved by the zone's sequencer committee, and only the block producer
//! includes its transactions.

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{SYSTEM_UPGRADER_ACCOUNT_ID, SystemProgramName};
use lee_core::{BlockId, account::AccountId, program::PdaSeed};
pub use sequencer_stake_core::SequencerKey;

const APPROVAL_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/SystemApproval/0000000";
const REGISTRY_SEED: [u8; 32] = *b"/LEZ/v0.3/SystemRegistry/0000000";

/// Top level only. Accounts are listed with the shard each selects. Variants are append-only.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Schedules `name` to switch to the chain at `first_segment` from block `from_height`.
    ///
    /// Accounts: the registry (this program's shard), the system program (the program loader's
    /// shard, a mutable header), the committee config (`sequencer_stake`'s shard).
    Schedule {
        name: SystemProgramName,
        first_segment: AccountId,
        from_height: BlockId,
        approvals: Vec<Approval>,
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
    /// Accounts: the registry, the committee config.
    Cancel {
        name: SystemProgramName,
        first_segment: AccountId,
        from_height: BlockId,
        approvals: Vec<Approval>,
    },
    /// Deploys a new, mutable system program `name` from the chain at `first_segment`.
    ///
    /// Accounts: the registry, the committee config, the system program (the program loader's
    /// shard, no header), then the chain in link order.
    Install {
        name: SystemProgramName,
        first_segment: AccountId,
        approvals: Vec<Approval>,
    },
}

impl Instruction {
    /// The change the committee approves, with its approvals; `None` for `Apply`.
    #[must_use]
    pub fn proposal(&self) -> Option<(Proposal, &[Approval])> {
        match self {
            Self::Schedule {
                name,
                first_segment,
                from_height,
                approvals,
            } => Some((
                Proposal::Schedule {
                    name: *name,
                    first_segment: *first_segment,
                    from_height: *from_height,
                },
                approvals,
            )),
            Self::Cancel {
                name,
                first_segment,
                from_height,
                approvals,
            } => Some((
                Proposal::Cancel {
                    name: *name,
                    first_segment: *first_segment,
                    from_height: *from_height,
                },
                approvals,
            )),
            Self::Install {
                name,
                first_segment,
                approvals,
            } => Some((
                Proposal::Install {
                    name: *name,
                    first_segment: *first_segment,
                },
                approvals,
            )),
            Self::Apply { .. } => None,
        }
    }
}

/// What the committee approves: the change itself, naming the action so an approval for one can't
/// be used for another.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Proposal {
    Schedule {
        name: SystemProgramName,
        first_segment: AccountId,
        from_height: BlockId,
    },
    Cancel {
        name: SystemProgramName,
        first_segment: AccountId,
        from_height: BlockId,
    },
    Install {
        name: SystemProgramName,
        first_segment: AccountId,
    },
}

/// One committee member's approval of a proposal, usable through block `valid_until`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Approval {
    pub signer: SequencerKey,
    pub valid_until: BlockId,
    /// Ed25519 signature over [`approval_message`].
    pub signature: Vec<u8>,
}

/// A pending upgrade, stored in the [`Registry`] under the system program's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ScheduledUpgrade {
    pub first_segment: AccountId,
    pub from_height: BlockId,
}

/// Every upgradable system program, by name, with its pending upgrade, if any. Stored at
/// [`registry_account_id`]: seeded at genesis, extended by `Install`.
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

/// Bytes a committee member signs. The channel id keeps an approval to one zone.
#[must_use]
pub fn approval_message(
    channel_id: [u8; 32],
    proposal: &Proposal,
    valid_until: BlockId,
) -> Vec<u8> {
    let mut message = APPROVAL_DOMAIN.to_vec();
    message.extend_from_slice(&channel_id);
    message.extend(borsh::to_vec(proposal).expect("a proposal serializes"));
    message.extend_from_slice(&valid_until.to_le_bytes());
    message
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
