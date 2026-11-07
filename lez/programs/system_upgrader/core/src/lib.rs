//! `system_upgrader`: upgrades and installs the system programs, each one of its PDAs
//! (`PdaSeed::for_system_program(name)`). Pending upgrades live in its registry. Every change but
//! `Apply` must be approved by the zone's sequencer committee, and only the block producer
//! includes its transactions.

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{SYSTEM_UPGRADER_ACCOUNT_ID, SystemProgramName};
use lee_core::{
    BlockId,
    account::{AccountId, Actor},
    program::{PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, ProgramId},
};
pub use sequencer_stake_core::{CommitteeApproval as Approval, SequencerKey};
use sequencer_stake_core::{
    committee_approval_message, sequencer_stake_account_id, sequencer_stake_config_account_id,
};

/// Separates the committee's approvals of system changes from its other approvals.
pub const APPROVAL_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/SystemApproval/0000000";
const REGISTRY_SEED: [u8; 32] = *b"/LEZ/v0.3/SystemRegistry/0000000";
const STAGING_PREFIX: [u8; 32] = *b"/LEZ/v0.3/SystemStaging/00000000";

/// Sent at the top level to the registry's actor ([`registry_actor`]). Variants are append-only.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message {
    /// Schedules `name` to switch to the chain at `first_segment` in block `activation_height`.
    /// Lands before that height; the loader validates the chain into a staging header.
    Schedule {
        name: SystemProgramName,
        first_segment: AccountId,
        image_id: ProgramId,
        activation_height: BlockId,
        approvals: Vec<Approval>,
    },
    /// Applies `name`'s pending upgrade and clears it. Valid only in block `activation_height`.
    Apply {
        name: SystemProgramName,
        activation_height: BlockId,
    },
    /// Clears `name`'s pending upgrade, before its activation height, if it is exactly this one.
    Cancel {
        name: SystemProgramName,
        first_segment: AccountId,
        activation_height: BlockId,
        approvals: Vec<Approval>,
    },
    /// Deploys a new, mutable system program `name` from the chain at `first_segment`.
    Install {
        name: SystemProgramName,
        first_segment: AccountId,
        image_id: ProgramId,
        approvals: Vec<Approval>,
    },
}

impl Message {
    /// The change the committee approves, with its approvals; `None` for `Apply`.
    #[must_use]
    pub fn proposal(&self) -> Option<(Proposal, &[Approval])> {
        match self {
            Self::Schedule {
                name,
                first_segment,
                image_id,
                activation_height,
                approvals,
            } => Some((
                Proposal::Schedule {
                    name: *name,
                    first_segment: *first_segment,
                    image_id: *image_id,
                    activation_height: *activation_height,
                },
                approvals,
            )),
            Self::Cancel {
                name,
                first_segment,
                activation_height,
                approvals,
            } => Some((
                Proposal::Cancel {
                    name: *name,
                    first_segment: *first_segment,
                    activation_height: *activation_height,
                },
                approvals,
            )),
            Self::Install {
                name,
                first_segment,
                image_id,
                approvals,
            } => Some((
                Proposal::Install {
                    name: *name,
                    first_segment: *first_segment,
                    image_id: *image_id,
                },
                approvals,
            )),
            Self::Apply { .. } => None,
        }
    }
}

/// What the committee approves: the change itself, naming the action so an approval for one can't
/// be used for another, and the image ID of the code it installs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum Proposal {
    Schedule {
        name: SystemProgramName,
        first_segment: AccountId,
        image_id: ProgramId,
        activation_height: BlockId,
    },
    Cancel {
        name: SystemProgramName,
        first_segment: AccountId,
        activation_height: BlockId,
    },
    Install {
        name: SystemProgramName,
        first_segment: AccountId,
        image_id: ProgramId,
    },
}

impl Proposal {
    /// What the committee signs over, after [`APPROVAL_DOMAIN`] and the channel id.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("a proposal serializes")
    }
}

/// A pending upgrade, stored in the [`Registry`] under the system program's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ScheduledUpgrade {
    pub first_segment: AccountId,
    /// What the chain at `first_segment` computes to, checked by the loader at `Schedule`.
    pub image_id: ProgramId,
    pub activation_height: BlockId,
}

/// Every upgradable system program, by name, with its pending upgrade, if any. Held in the
/// registry's actor state ([`registry_actor`]): seeded at genesis, extended by `Install`.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Registry {
    pub programs: BTreeMap<SystemProgramName, Option<ScheduledUpgrade>>,
}

impl Registry {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("a registry serializes")
    }

    /// An empty registry for an empty actor state.
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
    committee_approval_message(
        APPROVAL_DOMAIN,
        channel_id,
        &proposal.to_bytes(),
        valid_until,
    )
}

/// The sequencer committee's config, under `sequencer_stake`: it verifies approvals.
#[must_use]
pub fn committee_actor() -> Actor {
    let program = sequencer_stake_account_id();
    Actor::new(sequencer_stake_config_account_id(program), program)
}

/// Where the [`Registry`] lives: a PDA of `system_upgrader`.
#[must_use]
pub fn registry_account_id() -> AccountId {
    AccountId::for_public_pda(&SYSTEM_UPGRADER_ACCOUNT_ID, &PdaSeed::new(REGISTRY_SEED))
}

/// The actor every `system_upgrader` message is sent to: the registry, under `system_upgrader`.
#[must_use]
pub fn registry_actor() -> Actor {
    Actor::new(registry_account_id(), SYSTEM_UPGRADER_ACCOUNT_ID)
}

/// Where `Schedule` has the loader validate `upgrade`'s chain into a header, under the program
/// loader: a PDA of `system_upgrader`, one per proposal.
#[must_use]
pub fn staging_actor(name: &SystemProgramName, upgrade: &ScheduledUpgrade) -> Actor {
    Actor::new(
        AccountId::for_public_pda(&SYSTEM_UPGRADER_ACCOUNT_ID, &staging_seed(name, upgrade)),
        PROGRAM_LOADER_ACCOUNT_ID,
    )
}

/// The PDA seed of [`staging_actor`].
#[must_use]
pub fn staging_seed(name: &SystemProgramName, upgrade: &ScheduledUpgrade) -> PdaSeed {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(STAGING_PREFIX);
    hasher.update(name.as_bytes());
    hasher.update(upgrade.first_segment.value());
    hasher.update(borsh::to_vec(&upgrade.image_id).expect("an image ID serializes"));
    hasher.update(upgrade.activation_height.to_le_bytes());
    PdaSeed::new(hasher.finalize().into())
}

/// The system program `name`'s header, under the program loader.
#[must_use]
pub fn loader_actor(name: &SystemProgramName) -> Actor {
    Actor::new(
        AccountId::from_system_program_name(name),
        PROGRAM_LOADER_ACCOUNT_ID,
    )
}

/// `system_upgrader`'s fixed address.
#[must_use]
pub const fn system_upgrader_account_id() -> AccountId {
    SYSTEM_UPGRADER_ACCOUNT_ID
}
