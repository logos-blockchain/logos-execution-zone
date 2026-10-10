//! `system_upgrader` fixtures shared by the cycle cases, the `system_upgrader` criterion bench and
//! the smoke test: an upgrade of `clock`, approved by a committee of a chosen size.

use std::collections::BTreeMap;

use lee::{GenesisBuilder, PublicTransaction, V03State, program::Program, public_transaction};
use lee_core::{
    BlockId,
    account::{Account, AccountId, ProgramShardSelector, ShardData},
    program::{AccountMeta, PROGRAM_LOADER_ACCOUNT_ID, SYSTEM_UPGRADER_ACCOUNT_ID},
};
use sequencer_stake_core::{
    ChannelParams, SequencerEntry, SequencerKey, SequencerStakeConfig,
    ed25519_dalek::{Signer as _, SigningKey},
    sequencer_stake_account_id, sequencer_stake_config_account_id, slash_approval_threshold,
};
use system_upgrader_core::{
    Approval, Instruction, Proposal, Registry, approval_message, registry_account_id,
};

/// Committee sizes swept by `Schedule`: its approval checks grow with the committee.
pub const COMMITTEE_SIZES: [usize; 4] = [2, 4, 7, 10];
pub const SCHEDULE_BLOCK: BlockId = 1;
pub const FROM_HEIGHT: BlockId = 2;

const CHANNEL_ID: [u8; 32] = [5; 32];
const VALID_UNTIL: BlockId = 100;

/// The state an upgrade runs against, and the new code's segment chain.
pub struct Upgrade {
    pub state: V03State,
    pub segments: Vec<AccountId>,
    /// Bytes of the new code's user ELF: what `Apply`'s loader walk hashes.
    pub code_len: usize,
}

/// `system_upgrader`, a mutable, registered `clock`, a committee of `committee_size`, and
/// `new_code` uploaded as a segment chain.
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
        .with_named_programs([
            (
                programs::system_upgrader_account_id(),
                programs::system_upgrader(),
                false,
            ),
            (programs::clock_account_id(), programs::clock(), false),
        ])
        .with_public_accounts([registry(), committee_config(committee_size)])
        .with_public_accounts(segments.iter().zip(chain).map(|(id, segment)| {
            (
                *id,
                Account::default().with_shard(
                    PROGRAM_LOADER_ACCOUNT_ID,
                    segment
                        .to_loader_shard()
                        .try_into()
                        .expect("a built segment fits its shard"),
                ),
            )
        }))
        .build();
    Upgrade {
        state,
        segments,
        code_len: user_elf.len(),
    }
}

/// [`staged`], with the upgrade already scheduled.
#[must_use]
pub fn scheduled(committee_size: usize, new_code: &Program) -> Upgrade {
    let mut upgrade = staged(committee_size, new_code);
    let tx = schedule_tx(&upgrade.segments, committee_size);
    upgrade
        .state
        .transition_from_public_transaction(&tx, SCHEDULE_BLOCK, 0)
        .expect("the upgrade schedules");
    upgrade
}

/// `Schedule`, carrying approvals from a threshold of a committee of `committee_size`.
#[must_use]
pub fn schedule_tx(segments: &[AccountId], committee_size: usize) -> PublicTransaction {
    producer_tx(
        schedule_selectors(),
        schedule_instruction(segments, committee_size),
    )
}

/// `Apply` of the scheduled upgrade.
#[must_use]
pub fn apply_tx(segments: &[AccountId]) -> PublicTransaction {
    producer_tx(apply_selectors(segments), apply_instruction())
}

/// `Schedule`'s guest input: its accounts with their shards, and its instruction.
#[must_use]
pub fn schedule_guest_input(committee_size: usize) -> (Vec<(AccountMeta, ShardData)>, Instruction) {
    let upgrade = staged(committee_size, &programs::ping_receiver());
    let accounts = guest_accounts(&upgrade.state, &schedule_selectors());
    (
        accounts,
        schedule_instruction(&upgrade.segments, committee_size),
    )
}

/// `Apply`'s guest input, after the upgrade to `new_code` is scheduled.
#[must_use]
pub fn apply_guest_input(new_code: &Program) -> (Vec<(AccountMeta, ShardData)>, Instruction) {
    let upgrade = scheduled(2, new_code);
    let accounts = guest_accounts(&upgrade.state, &apply_selectors(&upgrade.segments));
    (accounts, apply_instruction())
}

/// An unsigned transaction, as the producer builds it.
fn producer_tx(
    selectors: Vec<ProgramShardSelector>,
    instruction: Instruction,
) -> PublicTransaction {
    let message = public_transaction::Message::try_new(
        SYSTEM_UPGRADER_ACCOUNT_ID,
        selectors,
        vec![],
        instruction,
    )
    .expect("a system_upgrader instruction serializes");
    PublicTransaction::new(
        message,
        public_transaction::WitnessSet::from_raw_parts(vec![]),
    )
}

fn guest_accounts(
    state: &V03State,
    selectors: &[ProgramShardSelector],
) -> Vec<(AccountMeta, ShardData)> {
    selectors
        .iter()
        .map(|selector| {
            let account = state.get_account_by_id(selector.account_id);
            (
                AccountMeta::new(selector.account_id, false, selector.program_account_id),
                account.data.shard(selector.program_account_id).clone(),
            )
        })
        .collect()
}

fn schedule_selectors() -> Vec<ProgramShardSelector> {
    vec![
        ProgramShardSelector::new(registry_account_id(), SYSTEM_UPGRADER_ACCOUNT_ID),
        ProgramShardSelector::new(programs::clock_account_id(), PROGRAM_LOADER_ACCOUNT_ID),
        ProgramShardSelector::new(committee_account_id(), sequencer_stake_account_id()),
    ]
}

fn apply_selectors(segments: &[AccountId]) -> Vec<ProgramShardSelector> {
    [
        ProgramShardSelector::new(registry_account_id(), SYSTEM_UPGRADER_ACCOUNT_ID),
        ProgramShardSelector::new(programs::clock_account_id(), PROGRAM_LOADER_ACCOUNT_ID),
    ]
    .into_iter()
    .chain(
        segments
            .iter()
            .map(|id| ProgramShardSelector::new(*id, PROGRAM_LOADER_ACCOUNT_ID)),
    )
    .collect()
}

fn schedule_instruction(segments: &[AccountId], committee_size: usize) -> Instruction {
    let first_segment = segments[0];
    let proposal = Proposal::Schedule {
        name: programs::CLOCK_NAME,
        first_segment,
        from_height: FROM_HEIGHT,
    };
    Instruction::Schedule {
        name: programs::CLOCK_NAME,
        first_segment,
        from_height: FROM_HEIGHT,
        approvals: approvals(&proposal, committee_size),
    }
}

const fn apply_instruction() -> Instruction {
    Instruction::Apply {
        name: programs::CLOCK_NAME,
        from_height: FROM_HEIGHT,
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

/// The registry with `clock` registered and nothing pending.
fn registry() -> (AccountId, Account) {
    let registry = Registry {
        programs: BTreeMap::from([(programs::CLOCK_NAME, None)]),
    };
    (
        registry_account_id(),
        Account::default().with_shard(
            SYSTEM_UPGRADER_ACCOUNT_ID,
            registry
                .to_bytes()
                .try_into()
                .expect("the registry fits its shard"),
        ),
    )
}

fn committee_config(committee_size: usize) -> (AccountId, Account) {
    let entries = (0..committee_size)
        .map(|index| {
            let seed = u8::try_from(index).expect("committee index fits in a byte");
            (
                sequencer_key(&committee_key(index)),
                SequencerEntry {
                    account_id: AccountId::new([seed.wrapping_add(1); 32]),
                    total_staked: 10,
                    total_pending_unstake: 0,
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
    (
        committee_account_id(),
        Account::default().with_shard(
            sequencer_stake_account_id(),
            config
                .to_bytes()
                .try_into()
                .expect("the committee config fits its shard"),
        ),
    )
}

fn committee_account_id() -> AccountId {
    sequencer_stake_config_account_id(sequencer_stake_account_id())
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
                .transition_from_public_transaction(&apply_tx(&upgrade.segments), FROM_HEIGHT, 0)
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
