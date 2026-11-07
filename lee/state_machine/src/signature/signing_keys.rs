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
