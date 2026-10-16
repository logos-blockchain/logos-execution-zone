//! `system_upgrader` fixtures shared by the cycle cases, the `system_upgrader` criterion bench and
//! the smoke test: an upgrade of `clock`, approved by a committee of a chosen size.

use std::collections::BTreeMap;

use lee::{GenesisBuilder, PublicTransaction, V03State, program::Program, public_transaction};
use lee_core::{
    BlockId,
    account::{Account, AccountId, Actor, ActorState},
    program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramId},
};
use program_loader_core::LoaderActorState as _;
use sequencer_stake_core::{
    ChannelParams, SequencerEntry, SequencerKey, SequencerStakeConfig,
    ed25519_dalek::{Signer as _, SigningKey},
    sequencer_stake_account_id, slash_approval_threshold,
};
use system_upgrader_core::{
    Approval, Message, Proposal, Registry, ScheduledUpgrade, approval_message, committee_actor,
    loader_actor, registry_actor, staging_actor,
};

/// Committee sizes swept by `Schedule`: its approval checks grow with the committee.
pub const COMMITTEE_SIZES: [usize; 4] = [2, 4, 7, 10];
pub const SCHEDULE_BLOCK: BlockId = 1;
pub const ACTIVATION_HEIGHT: BlockId = 2;

const CHANNEL_ID: [u8; 32] = [5; 32];
const VALID_UNTIL: BlockId = 100;

/// The state an upgrade runs against, and the new code's segment chain.
pub struct Upgrade {
    pub state: V03State,
    pub segments: Vec<AccountId>,
    /// The new code's image ID, which the committee approves.
    pub image_id: ProgramId,
    /// Bytes of the new code's user ELF: what `Apply`'s loader walk hashes.
    pub code_len: usize,
}

/// `system_upgrader`, `sequencer_stake`, a mutable, registered `clock`, a committee of
/// `committee_size`, and `new_code` uploaded as a segment chain.
#[must_use]
pub fn staged(committee_size: usize, new_code: &Program) -> Upgrade {
    let user_elf = risc0_binfmt::ProgramBinary::decode(new_code.elf())
        .expect("new code is a valid program binary")
        .user_elf
        .to_vec();
    let segments: Vec<AccountId> = (0..program_loader_core::segment_count(&user_elf))
        .map(|index| {
            let index = u8::try_from(index).expect("segment index fits in a byte");
            AccountId::new([0x40_u8.wrapping_add(index); 32])
        })
        .collect();
    let chain = program_loader_core::build_segments(&user_elf, &segments)
        .expect("new code splits into a segment chain");
    let state = GenesisBuilder::new()
        .with_programs_at([
            (
                programs::system_upgrader_account_id(),
                programs::system_upgrader(),
                false,
            ),
            (
                sequencer_stake_account_id(),
                programs::sequencer_stake(),
                false,
            ),
            (programs::clock_account_id(), programs::clock(), false),
        ])
        .with_public_accounts(
            [registry(), committee_config(committee_size)]
                .map(|(actor, data)| (actor.account_id, account_with(actor, data))),
        )
        .with_public_accounts(segments.iter().zip(chain).map(|(id, segment)| {
            (
                *id,
                Account::default().with_actor_state(
                    PROGRAM_LOADER_ACCOUNT_ID,
                    segment.to_loader_actor_state().into(),
                ),
            )
        }))
        .build();
    Upgrade {
        state,
        segments,
        image_id: new_code.id(),
        code_len: user_elf.len(),
    }
}

/// [`staged`], with the upgrade already scheduled.
#[must_use]
pub fn scheduled(committee_size: usize, new_code: &Program) -> Upgrade {
    let mut upgrade = staged(committee_size, new_code);
    let tx = schedule_tx(&upgrade, committee_size);
    upgrade
        .state
        .transition_from_public_transaction(&tx, SCHEDULE_BLOCK, 0)
        .expect("the upgrade schedules");
    upgrade
}

/// `Schedule`, carrying approvals from a threshold of a committee of `committee_size`.
#[must_use]
pub fn schedule_tx(upgrade: &Upgrade, committee_size: usize) -> PublicTransaction {
    producer_tx(
        &[committee_actor(), staging(upgrade)],
        &schedule_message(upgrade, committee_size),
    )
}

/// `Apply` of the scheduled upgrade.
#[must_use]
pub fn apply_tx() -> PublicTransaction {
    producer_tx(
        &[loader_actor(&programs::CLOCK_NAME)],
        &Message::Apply {
            name: programs::CLOCK_NAME,
            activation_height: ACTIVATION_HEIGHT,
        },
    )
}

/// `Schedule`'s guest input: the actor states it reads (the registry, the committee its approvals
/// go to, the staging header and `new_code`'s segment chain, which the loader validates) and its
/// message.
#[must_use]
pub fn schedule_guest_input(
    committee_size: usize,
    new_code: &Program,
) -> (Vec<(Actor, ActorState)>, Message) {
    let upgrade = staged(committee_size, new_code);
    let mut actor_states = vec![
        registry(),
        committee_config(committee_size),
        (staging(&upgrade), ActorState::empty()),
    ];
    actor_states.extend(upgrade.segments.iter().map(|id| {
        let actor = Actor::new(*id, PROGRAM_LOADER_ACCOUNT_ID);
        let data = upgrade
            .state
            .get_account_by_id(*id)
            .data
            .actor_state(PROGRAM_LOADER_ACCOUNT_ID)
            .clone();
        (actor, data)
    }));
    let message = schedule_message(&upgrade, committee_size);
    (actor_states, message)
}

/// Where `Schedule` has the loader validate `upgrade`'s chain.
fn staging(upgrade: &Upgrade) -> Actor {
    staging_actor(
        &programs::CLOCK_NAME,
        &ScheduledUpgrade {
            first_segment: upgrade.segments[0],
            image_id: upgrade.image_id,
            activation_height: ACTIVATION_HEIGHT,
        },
    )
}

/// An unsigned transaction to the registry, as the producer builds it.
fn producer_tx(actors: &[Actor], message: &Message) -> PublicTransaction {
    let message = public_transaction::Message::try_new(
        registry_actor(),
        std::iter::once(registry_actor()).chain(actors.iter().copied()),
        BTreeMap::new(),
        message,
    )
    .expect("a system_upgrader message serializes");
    PublicTransaction::new(
        message,
        public_transaction::WitnessSet::from_raw_parts(vec![]),
    )
}

fn schedule_message(upgrade: &Upgrade, committee_size: usize) -> Message {
    let proposal = Proposal::Schedule {
        name: programs::CLOCK_NAME,
        first_segment: upgrade.segments[0],
        image_id: upgrade.image_id,
        activation_height: ACTIVATION_HEIGHT,
    };
    Message::Schedule {
        name: programs::CLOCK_NAME,
        first_segment: upgrade.segments[0],
        image_id: upgrade.image_id,
        activation_height: ACTIVATION_HEIGHT,
        approvals: approvals(&proposal, committee_size),
    }
}

/// Approvals of `proposal` from exactly a threshold of the committee.
fn approvals(proposal: &Proposal, committee_size: usize) -> Vec<Approval> {
    (0..slash_approval_threshold(committee_size))
        .map(|index| {
            let key = committee_key(index);
            Approval {
                signer: sequencer_key(&key),
                valid_until: VALID_UNTIL,
                signature: key
                    .sign(&approval_message(CHANNEL_ID, proposal, VALID_UNTIL))
                    .to_bytes()
                    .to_vec(),
            }
        })
        .collect()
}

fn account_with(actor: Actor, data: ActorState) -> Account {
    Account::default().with_actor_state(actor.program_account_id, data)
}

/// The registry with `clock` registered and nothing pending.
fn registry() -> (Actor, ActorState) {
    let registry = Registry {
        programs: BTreeMap::from([(programs::CLOCK_NAME, None)]),
    };
    (registry_actor(), registry.to_bytes().into())
}

fn committee_config(committee_size: usize) -> (Actor, ActorState) {
    let entries = (0..committee_size)
        .map(|index| {
            let seed = u8::try_from(index).expect("committee index fits in a byte");
            (
                sequencer_key(&committee_key(index)),
                SequencerEntry {
                    account_id: AccountId::new([seed.wrapping_add(1); 32]),
                    total_staked: 10,
                    pending_unstake: None,
                },
            )
        })
        .collect();
    let config = SequencerStakeConfig {
        channel_params: Some(ChannelParams {
            minimum_sequencer_stake: 1,
            posting_timeframe: 1,
            posting_timeout: 2,
            exit_delay: 1,
        }),
        channel_id: Some(CHANNEL_ID),
        entries,
    };
    (committee_actor(), config.to_bytes().into())
}

fn committee_key(index: usize) -> SigningKey {
    let seed = u8::try_from(index).expect("committee index fits in a byte");
    SigningKey::from_bytes(&[seed.wrapping_add(1); 32])
}

fn sequencer_key(key: &SigningKey) -> SequencerKey {
    SequencerKey::new(key.verifying_key().to_bytes()).expect("a valid verifying key")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bench fixtures stay a working upgrade: if `system_upgrader` changes, this fails rather
    /// than the bench quietly timing a refused transaction.
    #[test]
    fn the_benched_upgrade_schedules_and_applies() {
        for committee_size in [2, 10] {
            let new_code = programs::sequencer_stake();
            let mut upgrade = scheduled(committee_size, &new_code);
            upgrade
                .state
                .transition_from_public_transaction(&apply_tx(), ACTIVATION_HEIGHT, 0)
                .expect("the upgrade applies");
            assert_eq!(
                upgrade
                    .state
                    .get_program_image_id(programs::clock_account_id()),
                Some(new_code.id())
            );
        }
    }
}
