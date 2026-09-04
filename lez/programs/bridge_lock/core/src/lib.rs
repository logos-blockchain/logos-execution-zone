//! Core types for the bridge-lock program, the source side of the cross-zone
//! token bridge. A holder locks part of their balance into an escrow and emits a
//! cross-zone message minting the wrapped token on the target zone.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{account::AccountId, program::PdaSeed};

const ESCROW_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/BridgeLockEscrow/0000/";
const CONFIG_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/BridgeLockCfg/0000000/";
const HOLDING_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/BridgeLockHold/000000/";

/// Variants are append-only. Borsh encodes the variant as a leading tag byte,
/// so inserting one ahead of `Lock` shifts every existing encoding.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Lock `amount` of the holder's balance and emit a cross-zone message
    /// minting the wrapped token on `target_zone`.
    ///
    /// `target_program_id` and `target_accounts` are supplied though the guest
    /// accepts one value for each: `cross_zone::extract_emission` reads them off
    /// the transaction, decoding every emitter through one shape.
    ///
    /// `target_zone` is the caller's, so a lock to a zone that will not route it
    /// escrows and never mints. TODO: bound it source-side.
    ///
    /// Required accounts (5): config PDA, holder (authorized, echoed), holder
    /// holding PDA, escrow PDA, outbox PDA.
    Lock {
        amount: u128,
        target_zone: [u8; 32],
        target_account_id: AccountId,
        target_accounts: Vec<[u8; 32]>,
        payload: Vec<u8>,
        ordinal: u32,
    },
    /// Pins the outbox program and the mint target, written once into a default
    /// config PDA at genesis. A re-run naming different programs is refused; an
    /// identical one is a no-op, which is what genesis replay does.
    ///
    /// Required accounts (1): the config PDA.
    InitConfig {
        outbox_account_id: AccountId,
        target_account_id: AccountId,
    },
}

/// PDA accumulating all locked balance on this zone.
#[must_use]
pub fn escrow_account_id(bridge_lock_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&bridge_lock_id, &escrow_seed())
}

#[must_use]
const fn escrow_seed() -> PdaSeed {
    PdaSeed::new(ESCROW_SEED_DOMAIN)
}

/// PDA holding one holder's bridgeable balance, debited by `Lock`.
#[must_use]
pub fn holding_account_id(bridge_lock_id: AccountId, holder: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(&bridge_lock_id, &holding_seed(holder))
}

#[must_use]
pub fn holding_seed(holder: &[u8; 32]) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(&HOLDING_SEED_DOMAIN);
    bytes[32..].copy_from_slice(holder);
    let seed: [u8; 32] = Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    PdaSeed::new(seed)
}

/// PDA holding the outbox program id and the mint target, seeded at genesis so
/// the guest can pin both without importing their image ids.
#[must_use]
pub fn config_account_id(bridge_lock_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&bridge_lock_id, &config_seed())
}

#[must_use]
const fn config_seed() -> PdaSeed {
    PdaSeed::new(CONFIG_SEED_DOMAIN)
}

/// Encodes the pinned outbox and mint target for the config account's data.
#[must_use]
pub fn config_bytes(outbox_account_id: AccountId, target_account_id: AccountId) -> [u8; 64] {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(outbox_account_id.as_ref());
    bytes[32..].copy_from_slice(target_account_id.as_ref());
    bytes
}

/// Decodes the pinned outbox and mint target from the config account's data.
#[must_use]
pub fn read_config(data: &[u8]) -> Option<(AccountId, AccountId)> {
    if data.len() < 64 {
        return None;
    }
    assert!(data.len() >= 64, "checked above");
    let outbox: [u8; 32] = data[..32].try_into().unwrap_or_else(|_| unreachable!());
    let target: [u8; 32] = data[32..64].try_into().unwrap_or_else(|_| unreachable!());
    Some((AccountId::new(outbox), AccountId::new(target)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escrow_is_stable() {
        let id = AccountId::new([4; 32]);
        assert_eq!(escrow_account_id(id), escrow_account_id(id));
    }

    #[test]
    fn config_ids_round_trip() {
        let outbox = AccountId::new([3; 32]);
        let target = AccountId::new([5; 32]);
        assert_eq!(
            read_config(&config_bytes(outbox, target)),
            Some((outbox, target))
        );
    }

    #[test]
    fn holding_is_unique_per_holder() {
        let id = AccountId::new([4; 32]);
        assert_ne!(
            holding_account_id(id, &[1; 32]),
            holding_account_id(id, &[2; 32])
        );
        assert_eq!(
            holding_account_id(id, &[1; 32]),
            holding_account_id(id, &[1; 32])
        );
    }

    /// `extract_emission` decodes `Lock` off peer transactions, so its tag byte is
    /// wire format: a variant inserted ahead of it would silently shift every
    /// existing encoding.
    #[test]
    fn lock_is_the_first_variant() {
        let lock = Instruction::Lock {
            amount: 1,
            target_zone: [7; 32],
            target_account_id: AccountId::new([1; 32]),
            target_accounts: vec![],
            payload: vec![],
            ordinal: 0,
        };
        let bytes = borsh::to_vec(&lock).expect("Lock serializes");
        assert_eq!(bytes[0], 0);
    }
}
