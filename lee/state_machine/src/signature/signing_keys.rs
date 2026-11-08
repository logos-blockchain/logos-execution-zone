use std::str::FromStr;

use lee_core::{
    account::{AccountId, Nonce},
    signing_key::{KeyType, SigningKeyState},
};
use rand::{Rng as _, rngs::OsRng};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    KeyScheme, PublicKeyOf, Schnorr, SecretKeyOf, SignatureScheme as _, Wots, WotsSecretKey,
};
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
    initial: Option<SigningKeyState>,
    next: SigningKeyState,
}

impl SigningSecret {
    fn new(
        secret: &PublicAccountSecret,
        key_type: KeyType,
        nonce: Nonce,
    ) -> (Self, SigningKeyState) {
        match key_type {
            KeyType::Wots => {
                let (sk, pk) = signing_key::<Wots>(secret, nonce);
                (Self::Wots(sk), Wots::key_state(&pk))
            }
            KeyType::Schnorr => {
                let (sk, pk) = signing_key::<Schnorr>(secret, nonce);
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
        let (signing_secret, current_key) = SigningSecret::new(secret, current, nonce);
        let initial = (nonce == Nonce(0)).then_some(current_key);
        let mut next_nonce = nonce;
        next_nonce.public_account_nonce_increment();
        Self {
            account_id: initial
                .and_then(|key| AccountId::for_initial_key(&key))
                .unwrap_or_else(|| public_account_id(secret)),
            secret: signing_secret,
            initial,
            next: key_state(secret, next, next_nonce),
        }
    }

    /// Signs with leaf `leaf` of a WOTS+ key's tree; a Schnorr key has a single key per nonce.
    ///
    /// # Panics
    ///
    /// If `leaf` is not below [`wots_tree::LEAVES`].
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

/// Per-nonce seed for one key type: `Sha256(DS_KEY_SEED || secret || key_type byte || nonce as
/// 16 bytes LE)`.
fn key_seed(secret: &PublicAccountSecret, key_type: KeyType, nonce: Nonce) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DS_KEY_SEED);
    hasher.update(secret.value());
    hasher.update(borsh::to_vec(&key_type).expect("a key type encodes to its discriminant byte"));
    hasher.update(nonce.0.to_le_bytes());
    hasher.finalize().into()
}

/// The account's key pair of scheme `K` at `nonce`.
#[must_use]
pub fn signing_key<K: KeyScheme>(
    secret: &PublicAccountSecret,
    nonce: Nonce,
) -> (SecretKeyOf<K>, PublicKeyOf<K>) {
    let mut seed = key_seed(secret, K::TYPE, nonce);
    let keys = K::Scheme::keygen(&seed);
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
    SigningSecret::new(secret, key_type, nonce).1
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;
    use crate::signature::Schnorr;

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
            key_seed(&secret, KeyType::Schnorr, Nonce(0)),
            hex!("fae55c59b7c627ad9eb58de366afbf662930f73911a32ef952b3a3710a251987")
        );
        assert_eq!(
            key_seed(&secret, KeyType::Schnorr, Nonce(1)),
            hex!("2e1b5e08998e9898270f477fc5868d07b07af996ac3b224250ffc2ded738289d")
        );
    }

    #[test]
    fn signing_key_known_answers() {
        let secret = PublicAccountSecret::new([7; 32]);
        for (nonce, expected_pk) in [
            (
                Nonce(0),
                hex!("5e4e66008d467f622ed19ccdecd33ac044cefc9e820da3f796cd79c6577c8139"),
            ),
            (
                Nonce(1),
                hex!("a24726717ac98b48fa5cf7cdc1878926de157bb84d3d11306436302caa78ee9a"),
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
}
