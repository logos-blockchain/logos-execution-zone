//! The account that names who sent a cross-zone delivery, and the delivery itself.

use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::account::ZoneId;
use lee_core::{account::AccountId, program::PdaSeed};

const SOURCE_MARKER_SEED_DOMAIN: [u8; 32] = *b"/LEZ/v0.3/CrossZoneSource/00000/";

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Delivery {
    pub src_zone: ZoneId,
    pub src_account_id: AccountId,
    pub payload: Vec<u8>,
}

/// The address a target derives from a delivery's deliverer and source, to authenticate its own
/// sources.
#[must_use]
pub fn inbox_source_marker_account_id(
    inbox_id: AccountId,
    src_zone: &ZoneId,
    src_account_id: AccountId,
) -> AccountId {
    AccountId::for_public_pda(
        &inbox_id,
        &inbox_source_marker_seed(src_zone, src_account_id),
    )
}

fn inbox_source_marker_seed(src_zone: &ZoneId, src_account_id: AccountId) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 96];
    bytes[..32].copy_from_slice(&SOURCE_MARKER_SEED_DOMAIN);
    bytes[32..64].copy_from_slice(src_zone);
    bytes[64..].copy_from_slice(src_account_id.as_ref());

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
    fn the_marker_separates_every_source() {
        let inbox = AccountId::new([1; 32]);
        let src = AccountId::new([9; 32]);
        let base = inbox_source_marker_account_id(inbox, &[7; 32], src);
        assert_eq!(base, inbox_source_marker_account_id(inbox, &[7; 32], src));
        assert_ne!(base, inbox_source_marker_account_id(inbox, &[8; 32], src));
        assert_ne!(
            base,
            inbox_source_marker_account_id(inbox, &[7; 32], AccountId::new([4; 32]))
        );
        assert_ne!(
            base,
            inbox_source_marker_account_id(AccountId::new([2; 32]), &[7; 32], src)
        );
    }
}
