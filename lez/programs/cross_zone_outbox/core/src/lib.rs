use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountId,
    program::{PdaSeed, ProgramId},
};
use serde::{Deserialize, Serialize};

const OUTBOX_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/CrossZoneOutbox/00000/";

/// Raw 32-byte zone (channel) id; the host maps it to the zone-sdk `ChannelId`.
pub type ZoneId = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    /// Records an outbound cross-zone message as a write to a self-owned PDA.
    ///
    /// Required accounts (1):
    /// - Outbox PDA account
    Emit {
        target_zone: ZoneId,
        target_program_id: ProgramId,
        /// Accounts the destination inbox must hand to the target program's
        /// chained call. The emitter specifies them; the watcher forwards them
        /// verbatim so the inbox stays target-agnostic.
        target_accounts: Vec<[u8; 32]>,
        payload: Vec<u8>,
        ordinal: u32,
    },
}

/// The message as stored in an outbox PDA. The destination zone's watcher reads
/// this from the inscribed block; the source coordinates are filled by the
/// watcher, not stored here.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct OutboxRecord {
    pub target_zone: ZoneId,
    pub target_program_id: ProgramId,
    pub target_accounts: Vec<[u8; 32]>,
    pub payload: Vec<u8>,
}

impl OutboxRecord {
    /// Borsh-encoded form stored in the outbox PDA's account data.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("OutboxRecord serializes")
    }

    /// Decodes an [`OutboxRecord`] from account data.
    pub fn from_bytes(bytes: &[u8]) -> borsh::io::Result<Self> {
        borsh::from_slice(bytes)
    }
}

/// PDA holding one emitted message, keyed by destination zone and a per-zone
/// ordinal.
#[must_use]
pub fn outbox_pda(outbox_id: ProgramId, target_zone: &ZoneId, ordinal: u32) -> AccountId {
    AccountId::for_public_pda(&outbox_id, &outbox_pda_seed(target_zone, ordinal))
}

/// Seed of an outbox message PDA, exposed so the guest can claim the account.
#[must_use]
pub fn outbox_pda_seed(target_zone: &ZoneId, ordinal: u32) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 68];
    bytes[..32].copy_from_slice(&OUTBOX_SEED_DOMAIN);
    bytes[32..64].copy_from_slice(target_zone);
    bytes[64..].copy_from_slice(&ordinal.to_le_bytes());

    let seed: [u8; 32] = Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    PdaSeed::new(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbox_pda_is_unique_per_zone_and_ordinal() {
        let id: ProgramId = [3; 8];
        let zone_a = [1; 32];
        let zone_b = [2; 32];

        assert_eq!(outbox_pda(id, &zone_a, 0), outbox_pda(id, &zone_a, 0));
        assert_ne!(outbox_pda(id, &zone_a, 0), outbox_pda(id, &zone_a, 1));
        assert_ne!(outbox_pda(id, &zone_a, 0), outbox_pda(id, &zone_b, 0));
    }
}
