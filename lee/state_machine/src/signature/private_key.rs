use std::str::FromStr;

use k256::elliptic_curve::{PrimeField as _, sec1::ToEncodedPoint as _};
use rand::{Rng as _, rngs::OsRng};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use sha2::{Digest as _, Sha256};

use crate::error::LeeError;

// TODO: Remove Debug, Clone, Serialize, Deserialize, PartialEq and Eq for security reasons
// TODO: Implement Zeroize
#[derive(Clone, SerializeDisplay, DeserializeFromStr, PartialEq, Eq)]
pub struct PrivateKey([u8; 32]);

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for PrivateKey {
    type Err = LeeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(s, &mut bytes).map_err(|_err| LeeError::InvalidPrivateKey)?;
        Self::try_new(bytes)
    }
}

impl PrivateKey {
    #[must_use]
    pub fn new_os_random() -> Self {
        let mut rng = OsRng;

        loop {
            if let Ok(key) = Self::try_new(rng.r#gen()) {
                break key;
            }
        }
    }

    fn is_valid_key(value: [u8; 32]) -> bool {
        k256::SecretKey::from_bytes(&value.into()).is_ok()
    }

    pub fn try_new(value: [u8; 32]) -> Result<Self, LeeError> {
        if Self::is_valid_key(value) {
            Ok(Self(value))
        } else {
            Err(LeeError::InvalidPrivateKey)
        }
    }

    #[must_use]
    pub const fn value(&self) -> &[u8; 32] {
        &self.0
    }

    /// `tweak` produces the "tweaked secret key" (`sk`) given a public account's `ssk`.
    /// We use "tweaked keys" to shield the public accounts' `ssk` against quantum threats.
    /// The "tweaked keys" are used for Schnorr Signatures (BIP-340).
    /// The usage of these keys will be greatly reduced once LEE is upgraded to use a PQ signatures.
    pub fn tweak(value: &[u8; 32]) -> Result<Self, LeeError> {
        if !Self::is_valid_key(*value) {
            return Err(LeeError::InvalidPrivateKey);
        }

        let sk = k256::SecretKey::from_slice(value).map_err(|_e| LeeError::InvalidPrivateKey)?;

        let hashed: [u8; 32] =
            Sha256::digest(sk.public_key().to_encoded_point(true).as_bytes()).into();

        let sk = sk.to_nonzero_scalar();

        let scalar = k256::Scalar::from_repr(hashed.into())
            .into_option()
            .ok_or(LeeError::InvalidPrivateKey)?;

        Self::try_new(sk.add(&scalar).to_bytes().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn value_getter() {
        let key = PrivateKey::try_new([1; 32]).unwrap();
        assert_eq!(key.value(), &key.0);
    }

    #[test]
    fn produce_key() {
        let _key = PrivateKey::new_os_random();
    }

    #[test]
    fn tweak_rejects_zero_key() {
        assert!(matches!(
            PrivateKey::tweak(&[0_u8; 32]),
            Err(LeeError::InvalidPrivateKey)
        ));
    }

    // tweak: 0xFF…FF exceeds the secp256k1 curve order
    #[test]
    fn tweak_rejects_out_of_range_key() {
        assert!(matches!(
            PrivateKey::tweak(&[0xFF; 32]),
            Err(LeeError::InvalidPrivateKey)
        ));
    }

    #[test]
    fn tweak_deterministic() {
        let tweaked = PrivateKey::tweak(&[1_u8; 32]).unwrap();
        assert_eq!(
            tweaked.value(),
            &[
                242, 210, 33, 19, 65, 108, 136, 176, 179, 128, 110, 210, 107, 193, 168, 112, 206,
                171, 86, 238, 131, 10, 39, 36, 44, 39, 246, 20, 46, 193, 204, 66
            ]
        );
    }
}
