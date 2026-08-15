//! This crate provides system accounts used by LEZ.

use std::str::FromStr as _;

use clock_core::ClockAccountData;
use lee_core::account::{Account, AccountId, Nonce};

#[must_use]
pub fn pinata_account_id() -> AccountId {
    // TODO: Use derivation from a public key?
    AccountId::from_str("EfQhKQAkX2FJiwNii2WFQsGndjvF1Mzd7RuVe7QdPLw7")
        .expect("Pinata program id should be valid")
}

#[must_use]
pub fn pinata_account() -> Account {
    Account {
        program_owner: loader_core::immutable_deploy_account_id(programs::pinata().id()),
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
        program_owner: loader_core::immutable_deploy_account_id(
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
        program_owner: loader_core::immutable_deploy_account_id(
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
pub fn clock_account() -> Account {
    Account {
        program_owner: loader_core::immutable_deploy_account_id(programs::clock().id()),
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
