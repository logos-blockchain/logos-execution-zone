//! The account that names who sent a cross-zone delivery.
//!
//! Its own crate because both the inbox, which derives the marker, and every
//! target that authenticates a source need the derivation, and nothing else. A
//! target linking the inbox's core for this would tie its image id, and every PDA
//! under it, to changes in the inbox's config types.

use lee_core::account::AccountId;

const SOURCE_MARKER_SEED_DOMAIN: AccountId = AccountId::new(*b"/LEZ/v0.3/CrossZoneSource/00000/");

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
///
/// Unlike claimed PDAs elsewhere in this crate, this address is never verified against a
/// real image id by the state machine (it is not a `Claim::Pda`), so it is a plain hash of
/// the inbox's and source's real dispatch addresses rather than a `for_public_pda`
/// derivation — both the inbox and every target already know these addresses without
/// needing to recover any `ProgramId`.
#[must_use]
pub fn inbox_source_marker_account_id(
    inbox_account_id: AccountId,
    src_zone: &ZoneId,
    src_account_id: AccountId,
) -> AccountId {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 128];
    bytes[..32].copy_from_slice(SOURCE_MARKER_SEED_DOMAIN.as_ref());
    bytes[32..64].copy_from_slice(inbox_account_id.value());
    bytes[64..96].copy_from_slice(src_zone);
    bytes[96..].copy_from_slice(src_account_id.value());

    let hash: [u8; 32] = Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .unwrap_or_else(|_| unreachable!());
    AccountId::new(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The address is the message: a different zone or a different source program
    /// must not land on the same account.
    #[test]
    fn the_marker_separates_every_source() {
        let inbox = AccountId::new([1; 32]);
        let base = inbox_source_marker_account_id(inbox, &[7; 32], AccountId::new([9; 32]));
        assert_eq!(
            base,
            inbox_source_marker_account_id(inbox, &[7; 32], AccountId::new([9; 32]))
        );
        assert_ne!(
            base,
            inbox_source_marker_account_id(inbox, &[8; 32], AccountId::new([9; 32]))
        );
        assert_ne!(
            base,
            inbox_source_marker_account_id(inbox, &[7; 32], AccountId::new([4; 32]))
        );
        assert_ne!(
            base,
            inbox_source_marker_account_id(
                AccountId::new([2; 32]),
                &[7; 32],
                AccountId::new([9; 32])
            )
        );
    }
}
