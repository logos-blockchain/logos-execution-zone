use std::str::FromStr;

use lee_core::{
    account::{AccountId, Nonce},
    signing_key::{KeyType, SigningKeyState},
};
use rand::{Rng as _, rngs::OsRng};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{KeyScheme, Schnorr, SignatureScheme as _, Wots, WotsSecretKey};
use crate::{PrivateKey, PublicKey};

const DS_KEY_SEED: &[u8; 32] =
    b"/LEE/v0.3/KeySeed/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

/// The type every public account's nonce-0 key has.
pub const INITIAL_KEY_TYPE: KeyType = KeyType::Wots;

/// A public account's secret: the root its per-nonce signing keys are derived from.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, SerializeDisplay, DeserializeFromStr)]
pub struct PublicAccountSecret([u8; 32]);

impl std::fmt::Debug for PublicAccountSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PublicAccountSecret(<redacted>)")
    }
}

impl std::fmt::Display for PublicAccountSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for PublicAccountSecret {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl PublicAccountSecret {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn new_os_random() -> Self {
        Self(OsRng.r#gen())
    }

    #[must_use]
    pub const fn value(&self) -> &[u8; 32] {
        &self.0
    }
}

enum SigningSecret {
    Schnorr(PrivateKey),
    Wots(WotsSecretKey),
}

/// One signer of a transaction: its key at its nonce in the message, and the key it rotates to.
pub struct Signer {
    account_id: AccountId,
    secret: SigningSecret,
    counter: u32,
    initial: Option<SigningKeyState>,
    next: SigningKeyState,
}

impl SigningSecret {
    fn new(
        secret: &PublicAccountSecret,
        key_type: KeyType,
        nonce: Nonce,
        counter: u32,
    ) -> (Self, SigningKeyState) {
        match key_type {
            KeyType::Wots => {
                let (sk, pk) = signing_key_with_counter::<Wots>(secret, nonce, counter);
                (Self::Wots(sk), Wots::key_state(&pk))
            }
            KeyType::Schnorr => {
                let (sk, pk) = signing_key_with_counter::<Schnorr>(secret, nonce, counter);
                (Self::Schnorr(sk), Schnorr::key_state(&pk))
            }
        }
    }

    fn auth_data(&self, message_with_keys: &[u8; 32]) -> Vec<u8> {
        match self {
            Self::Wots(sk) => Wots::sign(sk, message_with_keys).to_vec(),
            Self::Schnorr(sk) => Schnorr::auth_data(
                &PublicKey::new_from_private_key(sk),
                &Schnorr::sign(sk, message_with_keys),
            )
            .to_vec(),
        }
    }
}

impl Signer {
    /// Signs with the key of type `current` at `nonce` and rotates to the key of type `next` at
    /// the next nonce; at nonce 0 the entry also carries the initial key.
    #[must_use]
    pub fn new(
        secret: &PublicAccountSecret,
        nonce: Nonce,
        current: KeyType,
        next: KeyType,
    ) -> Self {
        let (signing_secret, current_key) = SigningSecret::new(secret, current, nonce, 0);
        let initial = (nonce == Nonce(0)).then_some(current_key);
        Self::build(secret, nonce, signing_secret, 0, initial, next)
    }

    /// Signs with the manually rotated key of type `current` at `(nonce, counter)` and rotates to
    /// the key of type `next` at the next nonce. A manually rotated key is stored on chain, so the
    /// entry never carries the initial key. At counter 0 this is [`Self::new`].
    #[must_use]
    pub fn new_with_counter(
        secret: &PublicAccountSecret,
        nonce: Nonce,
        counter: u32,
        current: KeyType,
        next: KeyType,
    ) -> Self {
        if counter == 0 {
            return Self::new(secret, nonce, current, next);
        }
        let (signing_secret, _) = SigningSecret::new(secret, current, nonce, counter);
        Self::build(secret, nonce, signing_secret, counter, None, next)
    }

    fn build(
        secret: &PublicAccountSecret,
        nonce: Nonce,
        signing_secret: SigningSecret,
        counter: u32,
        initial: Option<SigningKeyState>,
        next: KeyType,
    ) -> Self {
        let mut next_nonce = nonce;
        next_nonce.public_account_nonce_increment();
        Self {
            account_id: initial
                .and_then(|key| AccountId::for_initial_key(&key))
                .unwrap_or_else(|| public_account_id(secret)),
            secret: signing_secret,
            counter,
            initial,
            next: key_state(secret, next, next_nonce),
        }
    }

    /// Signs with leaf `leaf` of a WOTS+ key's tree; a Schnorr key has a single key per nonce.
    ///
    /// # Panics
    ///
    /// If `leaf` is not below [`WOTS_LEAVES`](super::WOTS_LEAVES).
    #[must_use]
    pub fn with_leaf(mut self, leaf: u8) -> Self {
        if let SigningSecret::Wots(sk) = self.secret {
            self.secret = SigningSecret::Wots(sk.with_leaf(leaf));
        }
        self
    }

    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// The rotation counter of the key it signs with: 0 unless the key was manually rotated.
    #[must_use]
    pub const fn counter(&self) -> u32 {
        self.counter
    }

    /// Whether the key signs with one of a tree's leaves, see [`Self::with_leaf`].
    #[must_use]
    pub const fn has_leaves(&self) -> bool {
        matches!(self.secret, SigningSecret::Wots(_))
    }

    #[must_use]
    pub const fn next(&self) -> SigningKeyState {
        self.next
    }

    /// The witness entry's authentication data over `message_with_keys`.
    #[must_use]
    pub fn auth_data(&self, message_with_keys: &[u8; 32]) -> Vec<u8> {
        let mut auth_data = self
            .initial
            .map(|key| borsh::to_vec(&key).expect("a signing key state encodes to 33 bytes"))
            .unwrap_or_default();
        auth_data.extend(self.secret.auth_data(message_with_keys));
        auth_data
    }
}

/// Seed for one key type at `(nonce, counter)`: `Sha256(DS_KEY_SEED || secret || key_type byte ||
/// nonce as 16 bytes LE || counter as 4 bytes LE)`.
fn key_seed(
    secret: &PublicAccountSecret,
    key_type: KeyType,
    nonce: Nonce,
    counter: u32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DS_KEY_SEED);
    hasher.update(secret.value());
    hasher.update(borsh::to_vec(&key_type).expect("a key type encodes to its discriminant byte"));
    hasher.update(nonce.0.to_le_bytes());
    hasher.update(counter.to_le_bytes());
    hasher.finalize().into()
}

/// The account's key pair of scheme `K` at `nonce`.
#[must_use]
pub fn signing_key<K: KeyScheme>(
    secret: &PublicAccountSecret,
    nonce: Nonce,
) -> (K::SecretKey, K::PublicKey) {
    signing_key_with_counter::<K>(secret, nonce, 0)
}

/// The account's key pair of scheme `K` at `(nonce, counter)`.
#[must_use]
pub fn signing_key_with_counter<K: KeyScheme>(
    secret: &PublicAccountSecret,
    nonce: Nonce,
    counter: u32,
) -> (K::SecretKey, K::PublicKey) {
    let mut seed = key_seed(secret, K::TYPE, nonce, counter);
    let keys = K::keygen(&seed);
    seed.zeroize();
    keys
}

/// The account's nonce-0 key state.
#[must_use]
pub fn initial_key(secret: &PublicAccountSecret) -> SigningKeyState {
    key_state(secret, INITIAL_KEY_TYPE, Nonce(0))
}

/// The id of the public account `secret` holds.
#[must_use]
pub fn public_account_id(secret: &PublicAccountSecret) -> AccountId {
    AccountId::for_initial_key(&initial_key(secret)).expect("the initial key type gives an id")
}

/// The account's key state of type `key_type` at `nonce`.
#[must_use]
pub fn key_state(secret: &PublicAccountSecret, key_type: KeyType, nonce: Nonce) -> SigningKeyState {
    key_state_with_counter(secret, key_type, nonce, 0)
}

/// The account's key state of type `key_type` at `(nonce, counter)`.
#[must_use]
pub fn key_state_with_counter(
    secret: &PublicAccountSecret,
    key_type: KeyType,
    nonce: Nonce,
    counter: u32,
) -> SigningKeyState {
    SigningSecret::new(secret, key_type, nonce, counter).1
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;
    use crate::signature::{Schnorr, authenticate, current_key};

    const KEY_TYPES: [KeyType; 2] = [KeyType::Wots, KeyType::Schnorr];

    #[test]
    fn signing_key_is_deterministic() {
        let secret = PublicAccountSecret::new([7; 32]);
        assert_eq!(
            signing_key::<Schnorr>(&secret, Nonce(0)),
            signing_key::<Schnorr>(&secret, Nonce(0))
        );
    }

    #[test]
    fn signing_keys_differ_per_nonce() {
        let secret = PublicAccountSecret::new([7; 32]);
        let (sk_0, pk_0) = signing_key::<Schnorr>(&secret, Nonce(0));
        let (sk_1, pk_1) = signing_key::<Schnorr>(&secret, Nonce(1));
        assert_ne!(sk_0, sk_1);
        assert_ne!(pk_0, pk_1);
    }

    #[test]
    fn key_seed_known_answers() {
        let secret = PublicAccountSecret::new([7; 32]);
        assert_eq!(
            key_seed(&secret, KeyType::Schnorr, Nonce(0), 0),
            hex!("eaca7ec391673b7eff1df595c6b49178370eac6f058513a106a23aabd9cc5146")
        );
        assert_eq!(
            key_seed(&secret, KeyType::Schnorr, Nonce(1), 0),
            hex!("bf06851877a683d6458f2ccd513e3c192c8ebb8b3ed03222a977d6dcfd6a5f50")
        );
        assert_eq!(
            key_seed(&secret, KeyType::Schnorr, Nonce(0), 1),
            hex!("15fec2392e5f990abb6fe3913855fa3b2dca89421274bf7f10b6108c6125323b")
        );
    }

    #[test]
    fn signing_key_known_answers() {
        let secret = PublicAccountSecret::new([7; 32]);
        for (nonce, expected_pk) in [
            (
                Nonce(0),
                hex!("131a37437833c9d76999d08d8c3de6b3cfec3fb78183df83ccd79dc2cf777b27"),
            ),
            (
                Nonce(1),
                hex!("d9c211fd55ac00606f57e677521eceed1bc6a7a88c1cf9197f2b3e56b3de633e"),
            ),
        ] {
            let (_sk, pk) = signing_key::<Schnorr>(&secret, nonce);
            assert_eq!(pk.value(), &expected_pk);
        }
    }

    #[test]
    fn derived_key_authenticates_against_its_key_state() {
        let (sk, pk) = signing_key::<Schnorr>(&PublicAccountSecret::new([7; 32]), Nonce(0));
        let state = Schnorr::key_state(&pk);
        let message = [1; 32];
        let auth = Schnorr::auth_data(&pk, &Schnorr::sign(&sk, &message));
        assert_eq!(state.key_type, KeyType::Schnorr);
        assert_eq!(
            Schnorr::precheck(&state.key_commitment, &auth).map(|(revealed, _sig)| revealed),
            Ok(pk)
        );
        assert_eq!(
            Schnorr::authenticate(&state.key_commitment, &message, &auth),
            Ok(())
        );
    }

    #[test]
    fn keys_differ_per_counter() {
        let secret = PublicAccountSecret::new([7; 32]);
        for key_type in KEY_TYPES {
            assert_ne!(
                key_state_with_counter(&secret, key_type, Nonce(3), 0),
                key_state_with_counter(&secret, key_type, Nonce(3), 1)
            );
        }
    }

    #[test]
    fn new_with_counter_at_zero_matches_new() {
        let secret = PublicAccountSecret::new([7; 32]);
        let message = [1; 32];
        for key_type in KEY_TYPES {
            // At nonce 0 the current key is the initial key, which is always WOTS+.
            let nonces = if key_type == INITIAL_KEY_TYPE {
                vec![Nonce(0), Nonce(1)]
            } else {
                vec![Nonce(1)]
            };
            for nonce in nonces {
                let plain = Signer::new(&secret, nonce, key_type, KeyType::Wots);
                let counted = Signer::new_with_counter(&secret, nonce, 0, key_type, KeyType::Wots);
                assert_eq!(counted.account_id(), plain.account_id());
                assert_eq!(counted.next(), plain.next());
                assert_eq!(counted.counter(), 0);

                let stored = (nonce != Nonce(0)).then(|| key_state(&secret, key_type, nonce));
                let auth_plain = plain.auth_data(&message);
                let auth_counted = counted.auth_data(&message);
                let (current_plain, rest_plain) =
                    current_key(stored, plain.account_id(), &auth_plain).unwrap();
                let (current_counted, rest_counted) =
                    current_key(stored, counted.account_id(), &auth_counted).unwrap();
                assert_eq!(current_counted, current_plain);
                for rest in [rest_plain, rest_counted] {
                    assert_eq!(
                        authenticate(&current_plain, &message, rest, &plain.next()),
                        Ok(plain.next())
                    );
                }
                if key_type == KeyType::Wots {
                    assert_eq!(auth_counted, auth_plain);
                }
            }
        }
    }

    #[test]
    fn new_with_counter_authenticates_against_the_stored_key() {
        let secret = PublicAccountSecret::new([7; 32]);
        let message = [1; 32];
        for key_type in KEY_TYPES {
            for (nonce, next_nonce) in [(Nonce(0), Nonce(1)), (Nonce(1), Nonce(2))] {
                let signer = Signer::new_with_counter(&secret, nonce, 1, key_type, KeyType::Wots);
                let stored = key_state_with_counter(&secret, key_type, nonce, 1);
                let auth_data = signer.auth_data(&message);

                let (current, rest) =
                    current_key(Some(stored), signer.account_id(), &auth_data).unwrap();
                assert_eq!(current, stored);
                assert_eq!(
                    authenticate(&current, &message, rest, &signer.next()),
                    Ok(signer.next())
                );
                assert_eq!(signer.next(), key_state(&secret, KeyType::Wots, next_nonce));
                assert_eq!(signer.account_id(), public_account_id(&secret));
                assert_eq!(signer.counter(), 1);
            }
        }
    }
}
