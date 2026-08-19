//! The account that names who sent a cross-zone delivery.
//!
//! Its own crate because both the inbox, which derives the marker, and every
//! target that authenticates a source need the derivation, and nothing else. A
//! target linking the inbox's core for this would tie its image id, and every PDA
//! under it, to changes in the inbox's config types.
//!
//! It is the coupling this buys back, not size: the derivation needs risc0's
//! sha, which is the bulk of what linking cost in the first place, so splitting
//! it out barely moves the guest.

use lee_core::{
    account::AccountId,
    program::{PdaSeed, ProgramId},
};

const SOURCE_MARKER_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/CrossZoneSource/00000/";

/// Raw 32-byte zone (channel) id.
pub type ZoneId = [u8; 32];

/// The account the inbox passes at position 0 of a delivery's chained call, so
/// the target can authenticate its own sources.
///
/// Nothing writes or claims it, and nothing can: crediting it would leave a
/// modified default-owner account, which the state machine rejects, and only the
/// inbox could claim this address, which it never does. So it stays
/// `Account::default()` and every hop round-trips it untouched.
///
/// The address is derivable by anyone, so it is not a secret and not a
/// capability. What makes it mean something is that a target checks it only after
/// pinning its caller to the inbox, and only the inbox can be that caller.
#[must_use]
pub fn inbox_source_marker_account_id(
    inbox_id: ProgramId,
    src_zone: &ZoneId,
    src_program_id: ProgramId,
) -> AccountId {
    AccountId::for_public_pda(
        &inbox_id,
        &inbox_source_marker_seed(src_zone, src_program_id),
    )
}

/// Seed of the source marker. Private: nothing claims this account, so no caller
/// needs the seed, only the address.
fn inbox_source_marker_seed(src_zone: &ZoneId, src_program_id: ProgramId) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 96];
    bytes[..32].copy_from_slice(&SOURCE_MARKER_SEED_DOMAIN);
    bytes[32..64].copy_from_slice(src_zone);
    for (word, chunk) in src_program_id.iter().zip(bytes[64..].chunks_exact_mut(4)) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }

    let seed: [u8; 32] = Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    PdaSeed::new(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The address is the message: a different zone or a different source program
    /// must not land on the same account.
    #[test]
    fn the_marker_separates_every_source() {
        let inbox: ProgramId = [1; 8];
        let base = inbox_source_marker_account_id(inbox, &[7; 32], [9; 8]);
        assert_eq!(
            base,
            inbox_source_marker_account_id(inbox, &[7; 32], [9; 8])
        );
        assert_ne!(
            base,
            inbox_source_marker_account_id(inbox, &[8; 32], [9; 8])
        );
        assert_ne!(
            base,
            inbox_source_marker_account_id(inbox, &[7; 32], [4; 8])
        );
        assert_ne!(
            base,
            inbox_source_marker_account_id([2; 8], &[7; 32], [9; 8])
        );
    }
}
