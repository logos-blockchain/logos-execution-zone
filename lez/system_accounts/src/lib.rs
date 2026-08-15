//! This crate provides system accounts used by LEZ.

use std::{collections::BTreeMap, str::FromStr as _};

use clock_core::ClockAccountData;
use lee_core::account::{Account, AccountId, Nonce};

// TODO: Replace with a real minimum value for testnet
/// Minimum summed stake for a Bedrock sequencer key to be a committee candidate.
pub const DEFAULT_MINIMUM_SEQUENCER_STAKE: u128 = 149;

/// Channel administration defaults.
///
/// Slots, not seconds (1 slot = 1s on the current devnet): 20-slot turns,
/// reclaimed after 10 idle slots if a sequencer stops posting — non-zero so
/// round robin can move on when a committee has more than one accredited key.
/// A lone-signature threshold still suffices for config changes.
pub const DEFAULT_SEQUENCER_POSTING_TIMEFRAME: Slots = 20;
pub const DEFAULT_SEQUENCER_POSTING_TIMEOUT: Slots = 10;
pub const DEFAULT_SEQUENCER_CONFIGURATION_THRESHOLD: u16 = 1;
pub const DEFAULT_SEQUENCER_WITHDRAW_THRESHOLD: u16 = 1;

pub type Slots = u32;

#[must_use]
pub fn pinata_account_id() -> AccountId {
    // TODO: Use derivation from a public key?
    AccountId::from_str("EfQhKQAkX2FJiwNii2WFQsGndjvF1Mzd7RuVe7QdPLw7")
        .expect("Pinata program id should be valid")
}

#[must_use]
pub fn pinata_account() -> Account {
    Account {
        program_owner: program_loader_core::immutable_deploy_account_id(programs::pinata().id()),
        balance: 1_500_000,
        // Difficulty: 3
        data: vec![3; 33].try_into().expect("Should fit"),
        nonce: Nonce::default(),
    }
}

#[must_use]
pub fn faucet_account_id() -> AccountId {
    faucet_core::compute_faucet_account_id(programs::faucet().id())
}

#[must_use]
pub fn faucet_account() -> Account {
    Account {
        program_owner: program_loader_core::immutable_deploy_account_id(
            programs::authenticated_transfer().id(),
        ),
        balance: u128::MAX,
        ..Account::default()
    }
}

#[must_use]
pub fn bridge_account_id() -> AccountId {
    bridge_core::compute_bridge_account_id(programs::bridge().id())
}

#[must_use]
pub fn bridge_account() -> Account {
    Account {
        program_owner: program_loader_core::immutable_deploy_account_id(
            programs::authenticated_transfer().id(),
        ),
        ..Account::default()
    }
}

#[must_use]
pub const fn clock_account_ids() -> [AccountId; 3] {
    clock_core::CLOCK_PROGRAM_ACCOUNT_IDS
}

#[must_use]
pub fn sequencer_stake_config_account_id() -> AccountId {
    sequencer_stake_core::sequencer_stake_config_account_id(programs::sequencer_stake().id())
}

/// Starts with no entries; every stake, including the bootstrap sequencer's
/// own, is added by replaying a `Stake` transaction, not seeded here.
#[must_use]
pub fn sequencer_stake_config_account() -> Account {
    Account {
        program_owner: programs::sequencer_stake().id().into(),
        data: sequencer_stake_core::SequencerStakeConfig {
            minimum_sequencer_stake: DEFAULT_MINIMUM_SEQUENCER_STAKE,
            entries: BTreeMap::new(),
        }
        .to_bytes()
        .try_into()
        .expect("sequencer stake config data should fit"),
        ..Account::default()
    }
}

#[must_use]
pub fn clock_account() -> Account {
    Account {
        program_owner: program_loader_core::immutable_deploy_account_id(programs::clock().id()),
        data: ClockAccountData {
            block_id: 0,
            timestamp: 0,
        }
        .to_bytes()
        .try_into()
        .expect("Clock account data should fit"),
        ..Account::default()
    }
}
