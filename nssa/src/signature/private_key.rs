use std::str::FromStr;

use rand::{Rng as _, rngs::OsRng};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::error::NssaError;

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
    type Err = NssaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(s, &mut bytes).map_err(|_err| NssaError::InvalidPrivateKey)?;
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

    pub fn try_new(value: [u8; 32]) -> Result<Self, NssaError> {
        if Self::is_valid_key(value) {
            Ok(Self(value))
        } else {
            Err(NssaError::InvalidPrivateKey)
        }
    }

    #[must_use]
    pub const fn value(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn tweak(value: &[u8; 32]) -> Result<Self, NssaError> {
        if !Self::is_valid_key(*value) {
            return Err(NssaError::InvalidPrivateKey);
        }

        let sk = secp256k1::SecretKey::from_byte_array(*value).expect("Expect a valid secret key");
        let pk = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk);

        let hashed: [u8; 32] = Impl::hash_bytes(&secp256k1::PublicKey::serialize(&pk))
            .as_bytes()
            .try_into()
            .expect("Sha256 outputs a 32-byte array");

        Self::try_new(
            sk.add_tweak(
                &secp256k1::Scalar::from_be_bytes(hashed).expect("Expect a valid secp256k1 Scalar"),
            )
            .expect("Expect a valid Scalar")
            .secret_bytes(),
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
