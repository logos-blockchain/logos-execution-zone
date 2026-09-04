//! This crate provides system accounts used by LEZ.

use std::collections::BTreeMap;

use clock_core::ClockAccountData;
use lee_core::account::{Account, AccountId};

// TODO: Replace with a real minimum value for testnet
/// Minimum summed stake for a Bedrock sequencer key to be a committee candidate.
pub const DEFAULT_MINIMUM_SEQUENCER_STAKE: u128 = 149;

/// Channel administration defaults, in slots (1 slot = 1s on the devnet).
///
/// A 300-slot turn is about twenty blocks at the 15s `block_create_timeout`,
/// and a turn nobody posts in passes on after 25. The timeout must stay above
/// that block interval, or a healthy sequencer loses its turn between its own
/// blocks.
pub const DEFAULT_SEQUENCER_POSTING_TIMEFRAME: Slots = 300;
pub const DEFAULT_SEQUENCER_POSTING_TIMEOUT: Slots = 25;
pub const DEFAULT_SEQUENCER_CONFIGURATION_THRESHOLD: u16 = 1;
pub const DEFAULT_SEQUENCER_WITHDRAW_THRESHOLD: u16 = 1;

pub type Slots = u32;

#[must_use]
pub fn faucet_account_id() -> AccountId {
    faucet_core::compute_faucet_account_id(programs::faucet().id().into())
}

#[must_use]
pub fn faucet_account() -> Account {
    Account {
        program_owner: programs::authenticated_transfer().id().into(),
        balance: u128::MAX,
        ..Account::default()
    }
}

#[must_use]
pub fn bridge_account_id() -> AccountId {
    bridge_core::compute_bridge_account_id(programs::bridge().id().into())
}

#[must_use]
pub fn bridge_account() -> Account {
    Account {
        program_owner: programs::authenticated_transfer().id().into(),
        ..Account::default()
    }
}

#[must_use]
pub fn fee_state_account_id() -> AccountId {
    fee_core::compute_fee_state_account_id(programs::fee().id().into())
}

#[must_use]
pub fn fee_escrow_account_id() -> AccountId {
    fee_core::compute_fee_escrow_account_id(programs::fee().id().into())
}

#[must_use]
pub fn fee_inbox_account_id() -> AccountId {
    fee_core::compute_fee_inbox_account_id(programs::fee().id().into())
}

/// Fee program account IDs in the order expected by the fee program.
#[must_use]
pub fn fee_account_ids() -> [AccountId; 3] {
    [
        fee_state_account_id(),
        fee_escrow_account_id(),
        fee_inbox_account_id(),
    ]
}

#[must_use]
pub fn fee_account() -> Account {
    Account {
        program_owner: programs::fee().id().into(),
        ..Account::default()
    }
}

/// The fee-state account at genesis: owned by the fee program, carrying the
/// genesis market state in its data.
#[must_use]
pub fn fee_state_account() -> Account {
    Account {
        program_owner: programs::fee().id().into(),
        data: fee_core::state::FeeState::genesis()
            .to_bytes()
            .try_into()
            .expect("FeeState data should fit"),
        ..Account::default()
    }
}

#[must_use]
pub const fn clock_account_ids() -> [AccountId; 3] {
    clock_core::CLOCK_PROGRAM_ACCOUNT_IDS
}

#[must_use]
pub fn sequencer_stake_config_account_id() -> AccountId {
    sequencer_stake_core::sequencer_stake_config_account_id(programs::sequencer_stake().id().into())
}

#[must_use]
pub fn stake_funds_account_id(ownership_id: &AccountId) -> AccountId {
    sequencer_stake_core::stake_funds_account_id(
        programs::sequencer_stake().id().into(),
        ownership_id,
    )
}

/// Starts with no entries; every stake, including the bootstrap sequencer's
/// own, is added by replaying a transaction, not seeded here.
///
/// Genesis passes `None` and lets the `InitChannelParams` transaction set the
/// params, so the base state is identical on every node whatever its own config
/// says. Tests that execute instructions without replaying genesis pass
/// `Some`.
#[must_use]
pub fn sequencer_stake_config_account(
    channel_params: Option<sequencer_stake_core::ChannelParams>,
) -> Account {
    Account {
        program_owner: programs::sequencer_stake().id().into(),
        data: sequencer_stake_core::SequencerStakeConfig {
            channel_params,
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
        program_owner: programs::clock().id().into(),
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
