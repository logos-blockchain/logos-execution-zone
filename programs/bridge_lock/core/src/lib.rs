//! Core types for the bridge-lock program, the source side of the cross-zone
//! token bridge. A holder locks part of their balance into an escrow and emits a
//! cross-zone message minting the wrapped token on the target zone.

use lee_core::{
    account::AccountId,
    program::{PdaSeed, ProgramId},
};
use serde::{Deserialize, Serialize};

const ESCROW_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/BridgeLockEscrow/0000/";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    /// Lock `amount` of the holder's balance and emit a cross-zone message
    /// minting the wrapped token on `target_zone`. The emission fields mirror
    /// `cross_zone_outbox::Instruction::Emit` so the watcher reads them directly.
    ///
    /// Required accounts (3): holder holding (authorized), escrow PDA, outbox PDA.
    Lock {
        amount: u128,
        target_zone: [u8; 32],
        target_program_id: ProgramId,
        target_accounts: Vec<[u8; 32]>,
        payload: Vec<u8>,
        outbox_program_id: ProgramId,
        ordinal: u32,
    },
}

/// PDA accumulating all locked balance on this zone.
#[must_use]
pub fn escrow_account_id(bridge_lock_id: ProgramId) -> AccountId {
    AccountId::for_public_pda(&bridge_lock_id, &escrow_seed())
}

#[must_use]
pub fn escrow_seed() -> PdaSeed {
    PdaSeed::new(ESCROW_SEED_DOMAIN)
}

/// Reads a bridgeable balance from account data; empty data is a zero balance.
#[must_use]
pub fn read_balance(data: &[u8]) -> u128 {
    if data.len() < 16 {
        return 0;
    }
    u128::from_le_bytes(data[..16].try_into().unwrap_or_else(|_| unreachable!()))
}

#[must_use]
pub fn balance_bytes(amount: u128) -> [u8; 16] {
    amount.to_le_bytes()
}

/// Builds the genesis holding account funding a holder's bridgeable balance:
/// owned by bridge_lock, data is the LE balance, at the holder's account id. It
/// is not produced by any transaction, so the sequencer and the indexer both
/// seed it through this one builder to keep their genesis states identical.
#[cfg(feature = "host")]
#[must_use]
pub fn build_holding_account(
    holder: AccountId,
    amount: u128,
) -> (AccountId, lee_core::account::Account) {
    let account = lee_core::account::Account {
        program_owner: lee::program::Program::bridge_lock().id(),
        data: balance_bytes(amount)
            .to_vec()
            .try_into()
            .expect("balance fits in account data"),
        ..Default::default()
    };
    (holder, account)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balance_round_trips() {
        assert_eq!(read_balance(&balance_bytes(7)), 7);
        assert_eq!(read_balance(&[]), 0);
    }

    #[test]
    fn escrow_is_stable() {
        let id: ProgramId = [4; 8];
        assert_eq!(escrow_account_id(id), escrow_account_id(id));
    }
}
