use std::str::FromStr;

use lee_core::{account::Nonce, signing_key::KeyType};
use rand::{Rng as _, rngs::OsRng};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{KeyScheme, PublicKeyOf, SecretKeyOf, SignatureScheme as _};

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
) -> (SecretKeyOf<K>, PublicKeyOf<K>) {
    let mut seed = key_seed(secret, K::TYPE, nonce);
    let keys = K::Scheme::keygen(&seed);
    seed.zeroize();
    keys
}
