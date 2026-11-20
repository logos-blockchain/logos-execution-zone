//! The rotation counter behind a public account's stored key. Ordinary keys use counter 0; a
//! manual rotation moves to the next counter at the same nonce.

use lee::signature::{PublicAccountSecret, key_state_with_counter};
use lee_core::{account::Nonce, signing_key::SigningKeyState};

/// The most manual rotations at one nonce the wallet searches for.
pub const MAX_ROTATIONS_PER_NONCE: u32 = 1024;

/// The counter at which `secret` derives `stored` at `nonce`.
pub fn matching_counter(
    secret: &PublicAccountSecret,
    stored: SigningKeyState,
    nonce: Nonce,
) -> Option<u32> {
    (0..=MAX_ROTATIONS_PER_NONCE)
        .find(|&counter| key_state_with_counter(secret, stored.key_type, nonce, counter) == stored)
}

#[cfg(test)]
mod tests {
    use lee_core::signing_key::KeyType;

    use super::*;

    const NONCE: Nonce = Nonce(4);

    fn secret() -> PublicAccountSecret {
        PublicAccountSecret::new([5; 32])
    }

    fn rotated(counter: u32) -> SigningKeyState {
        key_state_with_counter(&secret(), KeyType::Schnorr, NONCE, counter)
    }

    #[test]
    fn the_counter_of_the_stored_key_is_found() {
        assert_eq!(matching_counter(&secret(), rotated(0), NONCE), Some(0));
        assert_eq!(matching_counter(&secret(), rotated(2), NONCE), Some(2));
        assert_eq!(
            matching_counter(&secret(), rotated(MAX_ROTATIONS_PER_NONCE), NONCE),
            Some(MAX_ROTATIONS_PER_NONCE)
        );
    }

    #[test]
    fn a_key_from_another_nonce_or_secret_matches_no_counter() {
        assert_eq!(matching_counter(&secret(), rotated(1), Nonce(5)), None);
        let foreign = key_state_with_counter(
            &PublicAccountSecret::new([6; 32]),
            KeyType::Schnorr,
            NONCE,
            1,
        );
        assert_eq!(matching_counter(&secret(), foreign, NONCE), None);
    }
}
