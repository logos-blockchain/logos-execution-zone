use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, SlotRef},
    program::{PdaSeed, ProgramId},
};

/// Versions the seed layout: bump on any change to its field list or offsets,
/// so slots under an old layout can never be re-derived. Redundant with the
/// image id, which relocates every PDA in this crate whenever the crate changes,
/// but the two version different things.
const OUTBOX_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/CrossZoneOutbox/00001/";

/// Raw 32-byte zone (channel) id; the host maps it to the zone-sdk `ChannelId`.
pub type ZoneId = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Records an outbound cross-zone message as a write to this program's slot
    /// in a derived PDA.
    ///
    /// The slot is written once: a second `Emit` at the same
    /// `(emitter, target_zone, ordinal)` fails the transaction rather than
    /// replacing the record.
    ///
    /// Required accounts (1):
    /// - Outbox PDA account
    Emit {
        target_zone: ZoneId,
        target_program_id: ProgramId,
        /// Slots the destination inbox must hand to the target program's chained call.
        /// The emitter names both the account and the namespace, since only it knows what
        /// the target reads; the watcher forwards them verbatim so the inbox stays
        /// target-agnostic.
        target_accounts: Vec<SlotRef>,
        payload: Vec<u8>,
        ordinal: u32,
    },
}

/// One emitted message, as stored in its outbox PDA.
///
/// Carries the slot it occupies as well as the message, so a reader holding the
/// bytes knows who wrote them and where without inverting the address, which is
/// a hash. The source zone and block coordinates are filled by the destination's
/// watcher and are not stored here.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct OutboxRecord {
    /// The program that called `Emit`, which is the immediate chained caller.
    /// Cross-zone discovery names the top-level program instead, so joining a
    /// record against a delivery is only sound while every emitter refuses to be
    /// called by another program.
    pub emitter: ProgramId,
    pub target_zone: ZoneId,
    pub ordinal: u32,
    pub target_program_id: ProgramId,
    pub target_accounts: Vec<SlotRef>,
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

/// PDA holding one emitted message, keyed by the emitting program, the
/// destination zone, and a per-emitter per-zone ordinal.
///
/// `emitter` is the program that called `Emit`, which the guest takes from
/// `caller_program_id` rather than from the instruction. Without it in the
/// address two programs share a slot and one overwrites the other.
#[must_use]
pub fn outbox_pda(
    outbox_id: ProgramId,
    emitter: ProgramId,
    target_zone: &ZoneId,
    ordinal: u32,
) -> AccountId {
    AccountId::for_public_pda(&outbox_id, &outbox_pda_seed(emitter, target_zone, ordinal))
}

/// Seed of an outbox message PDA. Private: nothing outside the derivation needs
/// it, only the address.
fn outbox_pda_seed(emitter: ProgramId, target_zone: &ZoneId, ordinal: u32) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 100];
    bytes[..32].copy_from_slice(&OUTBOX_SEED_DOMAIN);
    for (word, chunk) in emitter.iter().zip(bytes[32..64].chunks_exact_mut(4)) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes[64..96].copy_from_slice(target_zone);
    bytes[96..].copy_from_slice(&ordinal.to_le_bytes());

    let seed: [u8; 32] = Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    PdaSeed::new(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTBOX: ProgramId = [3; 8];
    const EMITTER: ProgramId = [4; 8];

    #[test]
    fn outbox_pda_is_unique_per_zone_and_ordinal() {
        let zone_a = [1; 32];
        let zone_b = [2; 32];

        assert_eq!(
            outbox_pda(OUTBOX, EMITTER, &zone_a, 0),
            outbox_pda(OUTBOX, EMITTER, &zone_a, 0)
        );
        assert_ne!(
            outbox_pda(OUTBOX, EMITTER, &zone_a, 0),
            outbox_pda(OUTBOX, EMITTER, &zone_a, 1)
        );
        assert_ne!(
            outbox_pda(OUTBOX, EMITTER, &zone_a, 0),
            outbox_pda(OUTBOX, EMITTER, &zone_b, 0)
        );
    }

    /// Two programs emitting to the same zone and ordinal must not share a slot,
    /// or the second silently overwrites the first.
    #[test]
    fn outbox_pda_is_unique_per_emitter() {
        let zone = [1; 32];
        let other: ProgramId = [5; 8];

        assert_ne!(
            outbox_pda(OUTBOX, EMITTER, &zone, 0),
            outbox_pda(OUTBOX, other, &zone, 0)
        );
    }

    #[test]
    fn outbox_record_round_trips() {
        let record = OutboxRecord {
            emitter: EMITTER,
            target_zone: [1; 32],
            ordinal: 7,
            target_program_id: [6; 8],
            target_accounts: vec![SlotRef::new(AccountId::new([9; 32]), [6; 8])],
            payload: b"payload".to_vec(),
        };

        assert_eq!(
            OutboxRecord::from_bytes(&record.to_bytes()).expect("record decodes"),
            record
        );
    }
}
