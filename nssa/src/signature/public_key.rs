use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::account::AccountId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{PrivateKey, error::NssaError};

#[derive(Clone, PartialEq, Eq, BorshSerialize, Serialize, Deserialize)]
pub struct PublicKey([u8; 32]);

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf)?;

        Self::try_new(buf).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid public key: not a valid point",
            )
        })
    }
}

impl PublicKey {
    pub fn new_from_private_key(key: &PrivateKey) -> Self {
        let value = {
            let secret_key = secp256k1::SecretKey::from_byte_array(*key.value()).unwrap();
            let public_key =
                secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret_key);
            let (x_only, _) = public_key.x_only_public_key();
            x_only.serialize()
        };
        Self(value)
    }

    pub fn try_new(value: [u8; 32]) -> Result<Self, NssaError> {
        // Check point is valid
        let _ = secp256k1::XOnlyPublicKey::from_byte_array(value)
            .map_err(|_| NssaError::InvalidPublicKey)?;
        Ok(Self(value))
    }

    pub fn value(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<&PublicKey> for AccountId {
    fn from(key: &PublicKey) -> Self {
        const PUBLIC_ACCOUNT_ID_PREFIX: &[u8; 32] =
            b"/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00";

        let mut hasher = Sha256::new();
        hasher.update(PUBLIC_ACCOUNT_ID_PREFIX);
        hasher.update(key.0);
        Self::new(hasher.finalize().into())
    }
}

#[cfg(test)]
mod test {
    use crate::{PublicKey, error::NssaError, signature::bip340_test_vectors};

    #[test]
    fn test_try_new_invalid_public_key_from_bip340_test_vectors_5() {
        let value_invalid_key = [
            238, 253, 234, 76, 219, 103, 119, 80, 164, 32, 254, 232, 7, 234, 207, 33, 235, 152,
            152, 174, 121, 185, 118, 135, 102, 228, 250, 160, 74, 45, 74, 52,
        ];

        let result = PublicKey::try_new(value_invalid_key);

        assert!(matches!(result, Err(NssaError::InvalidPublicKey)));
    }

    #[test]
    fn test_try_new_invalid_public_key_from_bip340_test_vector_14() {
        let value_invalid_key = [
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 252, 48,
        ];

        let result = PublicKey::try_new(value_invalid_key);

        assert!(matches!(result, Err(NssaError::InvalidPublicKey)));
    }

    #[test]
    fn test_try_new_valid_public_keys() {
        for (i, test_vector) in bip340_test_vectors::test_vectors().into_iter().enumerate() {
            let expected_public_key = test_vector.pubkey;
            let public_key = PublicKey::try_new(*expected_public_key.value()).unwrap();
            assert_eq!(public_key, expected_public_key, "Failed on test vector {i}");
        }
    }

    #[test]
    fn test_public_key_generation_from_bip340_test_vectors() {
        for (i, test_vector) in bip340_test_vectors::test_vectors().into_iter().enumerate() {
            let Some(private_key) = &test_vector.seckey else {
                continue;
            };
            let public_key = PublicKey::new_from_private_key(private_key);
            let expected_public_key = &test_vector.pubkey;
            assert_eq!(
                &public_key, expected_public_key,
                "Failed test vector at index {i}"
            );
        }
    }

    #[test]
    fn test_correct_ser_deser_roundtrip() {
        let pub_key = PublicKey::try_new([42; 32]).unwrap();

        let pub_key_borsh_ser = borsh::to_vec(&pub_key).unwrap();
        let pub_key_new: PublicKey = borsh::from_slice(&pub_key_borsh_ser).unwrap();

        assert_eq!(pub_key, pub_key_new);
    }
}
