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

    pub fn tweak(value: &[u8; 32]) -> Result<Self, LeeError> {
        assert!(Self::is_valid_key(*value));

        let sk = k256::SecretKey::from_bytes(value.into()).expect("Expect a valid secret key");

        let mut bytes = vec![];
        let pk = sk.public_key();
        bytes.extend_from_slice(pk.to_encoded_point(true).as_bytes());
        let hashed: [u8; 32] = Sha256::digest(&bytes).into();

        Self::try_new(
            k256::Scalar::from_repr((*value).into())
                .expect("Expect a valid k256 scalar")
                .add(&k256::Scalar::from_repr(hashed.into()).expect("Expect a valid k256 scalar"))
                .to_bytes()
                .into(),
>>>>>>> b2e99c4a (clippy fixes):nssa/src/signature/private_key.rs
        )
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
}
