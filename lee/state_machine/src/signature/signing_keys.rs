use std::str::FromStr;

use lee_core::{account::Nonce, signing_key::KeyType};
use rand::{Rng as _, rngs::OsRng};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::KeyScheme;

const DS_KEY_SEED: &[u8; 32] =
    b"/LEE/v0.3/KeySeed/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

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
) -> (K::SecretKey, K::PublicKey) {
    let mut seed = key_seed(secret, K::TYPE, nonce);
    let keys = K::keygen(&seed);
    seed.zeroize();
    keys
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;
    use crate::signature::{Schnorr, SignatureScheme as _};

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
            hex!("68256777fe99e612069c47cf884d5d3ca225b6caa113df93d847859c99cf5ab1")
        );
        assert_eq!(
            key_seed(&secret, KeyType::Schnorr, Nonce(1)),
            hex!("5994302e299bf9e059ce56b00574b1224032a9aa669243a8e1a8ba100eca0c43")
        );
    }

    #[test]
    fn signing_key_known_answers() {
        let secret = PublicAccountSecret::new([7; 32]);
        for (nonce, expected_pk) in [
            (
                Nonce(0),
                hex!("c633dbb2522dd340094b469d8a4b2acb067731140e2e4880978269116aa05d8c"),
            ),
            (
                Nonce(1),
                hex!("c0ed4b72427094127108dc89df6134b26db2ff3646308e57e064de64d24db8aa"),
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
