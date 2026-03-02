use rand::{Rng, rngs::OsRng};
use risc0_zkvm::sha::{Impl, Sha256};
use serde::{Deserialize, Serialize};

use crate::error::NssaError;

// TODO: Remove Debug, Clone, Serialize, Deserialize, PartialEq and Eq for security reasons
// TODO: Implement Zeroize
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateKey([u8; 32]);

impl PrivateKey {
    pub fn new_os_random() -> Self {
        let mut rng = OsRng;

        loop {
            match Self::try_new(rng.r#gen()) {
                Ok(key) => break key,
                Err(_) => continue,
            };
        }
    }

    fn is_valid_key(value: [u8; 32]) -> bool {
        secp256k1::SecretKey::from_byte_array(value).is_ok()
    }

    pub fn try_new(value: [u8; 32]) -> Result<Self, NssaError> {
        if Self::is_valid_key(value) {
            Ok(Self(value))
        } else {
            Err(NssaError::InvalidPrivateKey)
        }
    }

    pub fn value(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn tweak(value: &[u8; 32]) -> Result<Self, NssaError> {
        assert!(Self::is_valid_key(*value));

        let sk = secp256k1::SecretKey::from_byte_array(*value).unwrap();

        let mut bytes = vec![];
        let pk = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk);
        bytes.extend_from_slice(&secp256k1::PublicKey::serialize(&pk));
        let hashed: [u8; 32] = Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap();

        PrivateKey::try_new(
            sk.add_tweak(&secp256k1::Scalar::from_be_bytes(hashed).unwrap())
                .expect("Expect a valid Scalar")
                .secret_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_value_getter() {
        let key = PrivateKey::try_new([1; 32]).unwrap();
        assert_eq!(key.value(), &key.0);
    }

    #[test]
    fn test_produce_key() {
        let _key = PrivateKey::new_os_random();
    }
}
