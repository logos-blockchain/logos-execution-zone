//! Core types for the bridge-lock program, the source side of the cross-zone
//! token bridge. A holder locks part of their balance into an escrow and emits a
//! cross-zone message minting the wrapped token on the target zone.

use borsh::{BorshDeserialize, BorshSerialize};
pub use cross_zone_emission_core::{CrossZoneEmission, ZoneId};
use lee_core::{
    account::{AccountId, Actor},
    program::PdaSeed,
};

const ESCROW_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/BridgeLockEscrow/0000/";
const CONFIG_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/BridgeLockCfg/0000000/";
const HOLDING_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/BridgeLockHold/000000/";

pub const BRIDGE_LOCK_NAME: [u8; 11] = *b"bridge_lock";

/// Variants are append-only. Borsh encodes the variant as a leading tag byte,
/// so inserting one ahead of `Lock` shifts every existing encoding.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message {
    /// Lock `amount` of the holder's balance and emit a cross-zone message
    /// minting the wrapped token on the emission's target zone.
    ///
    /// The emission's target fields are supplied though the guest accepts one
    /// value for each: `cross_zone::extract_emission` reads them off the
    /// transaction, decoding every emitter through one shape.
    ///
    /// The target zone is the caller's, so the config pins it: a lock to a zone
    /// this zone does not lock to is refused.
    ///
    /// Sent to the holder's own actor under this program, signed by the holder;
    /// `outbox` is the outbox PDA actor the emission goes to. The trailing
    /// fields are the emission wire contract.
    Lock {
        outbox: Actor,
        amount: u128,
        emission: CrossZoneEmission,
    },
    /// Written once into the config actor state at genesis. Repeating the same
    /// configuration is a no-op; a different one is rejected.
    ///
    /// Sent to the config PDA.
    InitConfig {
        outbox_account_id: AccountId,
        target_account_id: AccountId,
        lock_target_zones: Vec<ZoneId>,
    },
    CheckRoute {
        outbox_account_id: AccountId,
        target_account_id: AccountId,
        target_zone: ZoneId,
    },
}

#[must_use]
pub fn bridge_lock_account_id() -> AccountId {
    AccountId::from_builtin_program_name(&BRIDGE_LOCK_NAME)
}

/// PDA accumulating all locked balance on this zone.
#[must_use]
pub fn escrow_account_id(bridge_lock_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&bridge_lock_id, &escrow_seed())
}

#[must_use]
pub const fn escrow_seed() -> PdaSeed {
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

/// PDA holding the outbox program id, the mint target and the zones this zone
/// locks to, seeded at genesis so the guest pins them without hardcoding any
/// ids.
#[must_use]
pub fn config_account_id(bridge_lock_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&bridge_lock_id, &config_seed())
}

#[must_use]
pub const fn config_seed() -> PdaSeed {
    PdaSeed::new(CONFIG_SEED_DOMAIN)
}

#[must_use]
pub fn config_bytes(
    outbox_account_id: AccountId,
    target_account_id: AccountId,
    lock_target_zones: &[ZoneId],
) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(64_usize.saturating_add(lock_target_zones.len().saturating_mul(32)));
    bytes.extend_from_slice(outbox_account_id.as_ref());
    bytes.extend_from_slice(target_account_id.as_ref());
    for zone in lock_target_zones {
        bytes.extend_from_slice(zone);
    }
    bytes
}

/// `None` unless the tail is whole zone ids: a partial tail would silently drop
/// a zone from the pinned list.
#[must_use]
pub fn read_config(data: &[u8]) -> Option<(AccountId, AccountId, Vec<ZoneId>)> {
    let (pinned, tail) = data.split_at_checked(64)?;
    let (zones, remainder) = tail.as_chunks::<32>();
    if !remainder.is_empty() {
        return None;
    }
    let outbox: [u8; 32] = pinned[..32].try_into().unwrap_or_else(|_| unreachable!());
    let target: [u8; 32] = pinned[32..].try_into().unwrap_or_else(|_| unreachable!());
    Some((
        AccountId::new(outbox),
        AccountId::new(target),
        zones.to_vec(),
    ))
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
        for zones in [Vec::new(), vec![[7; 32]], vec![[7; 32], [8; 32], [9; 32]]] {
            assert_eq!(
                read_config(&config_bytes(outbox, target, &zones)),
                Some((outbox, target, zones))
            );
        }
    }

    #[test]
    fn a_config_that_is_not_whole_zone_ids_is_refused() {
        let bytes = config_bytes(AccountId::new([3; 32]), AccountId::new([5; 32]), &[[7; 32]]);
        assert_eq!(read_config(&bytes[..bytes.len().saturating_sub(1)]), None);
        assert_eq!(read_config(&bytes[..63]), None);
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
        let outbox = Actor::new(AccountId::new([2; 32]), AccountId::new([3; 32]));
        let emission = CrossZoneEmission {
            target_zone: [7; 32],
            target_account_id: AccountId::new([1; 32]),
            target_accounts: vec![],
            payload: vec![],
            ordinal: 0,
        };
        let lock = Message::Lock {
            outbox,
            amount: 1,
            emission: emission.clone(),
        };
        let bytes = borsh::to_vec(&lock).expect("Lock serializes");

        let mut expected = vec![0];
        expected.extend(borsh::to_vec(&outbox).expect("outbox serializes"));
        expected.extend(1_u128.to_le_bytes());
        expected.extend(borsh::to_vec(&emission).expect("emission serializes"));
        assert_eq!(
            bytes, expected,
            "Lock is the tag, the outbox actor, the amount, then the emission wire fields"
        );
    }
}
