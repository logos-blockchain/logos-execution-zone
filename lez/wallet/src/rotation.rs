//! The rotation counter behind a public account's stored key. Ordinary keys use counter 0; a
//! manual rotation moves to the next counter at the same nonce.

use anyhow::{Result, bail};
use lee::signature::{PublicAccountSecret, key_state_with_counter};
use lee_core::{account::Nonce, signing_key::SigningKeyState};

/// The most manual rotations at one nonce the wallet searches for and makes.
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

/// The counter a manual rotation at `nonce` moves to. A stored key `secret` does not derive at
/// `nonce` is replaced at counter 1.
pub fn next_counter(
    secret: &PublicAccountSecret,
    stored: Option<SigningKeyState>,
    nonce: Nonce,
) -> Result<u32> {
    let current = stored
        .and_then(|stored| matching_counter(secret, stored, nonce))
        .unwrap_or(0);
    match current.checked_add(1) {
        Some(next) if next <= MAX_ROTATIONS_PER_NONCE => Ok(next),
        _ => bail!(
            "The key was rotated manually {MAX_ROTATIONS_PER_NONCE} times at this nonce: sign a \
             transaction with it before rotating again"
        ),
    }
}

#[cfg(test)]
mod tests {
    use lee::signature::key_state;
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

    #[test]
    fn a_rotation_takes_the_next_counter() {
        assert_eq!(next_counter(&secret(), None, NONCE).unwrap(), 1);
        assert_eq!(
            next_counter(
                &secret(),
                Some(key_state(&secret(), KeyType::Schnorr, NONCE)),
                NONCE
            )
            .unwrap(),
            1
        );
        assert_eq!(next_counter(&secret(), Some(rotated(3)), NONCE).unwrap(), 4);
    }

    /// A rotation built at the previous nonce that landed after a signed transaction.
    #[test]
    fn a_key_from_another_nonce_is_replaced_at_counter_one() {
        let landed_late = key_state_with_counter(&secret(), KeyType::Schnorr, Nonce(3), 1);
        assert_eq!(
            next_counter(&secret(), Some(landed_late), NONCE).unwrap(),
            1
        );
    }

    #[test]
    fn rotations_stop_at_the_cap() {
        let error =
            next_counter(&secret(), Some(rotated(MAX_ROTATIONS_PER_NONCE)), NONCE).unwrap_err();
        assert!(error.to_string().contains("sign a transaction"), "{error}");
    }
}
