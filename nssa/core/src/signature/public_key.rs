use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::{PrivateKey, error::NssaCoreError};

#[derive(Clone, PartialEq, Eq, BorshSerialize, SerializeDisplay, DeserializeFromStr)]
pub struct PublicKey([u8; 32]);

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for PublicKey {
    type Err = NssaCoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(s, &mut bytes).map_err(NssaCoreError::InvalidHexPublicKey)?;
        Self::try_new(bytes)
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = [0_u8; 32];
        reader.read_exact(&mut buf)?;

        Self::try_new(buf).map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }
}

impl PublicKey {
    #[must_use]
    pub fn new_from_private_key(key: &PrivateKey) -> Self {
        let value = {
            let secret_key = k256::SecretKey::from_bytes(&(*key.value()).into())
                .expect("Expect a valid private key");

            let encoded = secret_key.public_key().to_encoded_point(false);
            let x_only = encoded
                .x()
                .expect("Expect k256 point to have a x-coordinate");

            *x_only.first_chunk().expect("x_only is exactly 32 bytes")
        };
        Self(value)
    }

    pub fn try_new(value: [u8; 32]) -> Result<Self, NssaCoreError> {
        // Check point is a valid x-only public key
        let _ = k256::schnorr::VerifyingKey::from_bytes(&value)
            .map_err(NssaCoreError::InvalidPublicKey)?;

        Ok(Self(value))
    }

    #[must_use]
    pub const fn value(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod test {
    use crate::{PublicKey, error::NssaCoreError, signature::bip340_test_vectors};

    #[test]
    fn try_new_invalid_public_key_from_bip340_test_vectors_5() {
        let value_invalid_key = [
            238, 253, 234, 76, 219, 103, 119, 80, 164, 32, 254, 232, 7, 234, 207, 33, 235, 152,
            152, 174, 121, 185, 118, 135, 102, 228, 250, 160, 74, 45, 74, 52,
        ];

        let result = PublicKey::try_new(value_invalid_key);

        assert!(matches!(result, Err(NssaCoreError::InvalidPublicKey(_))));
    }

    #[test]
    fn try_new_invalid_public_key_from_bip340_test_vector_14() {
        let value_invalid_key = [
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 252, 48,
        ];

        let result = PublicKey::try_new(value_invalid_key);

        assert!(matches!(result, Err(NssaCoreError::InvalidPublicKey(_))));
    }

    #[test]
    fn try_new_valid_public_keys() {
        for (i, test_vector) in bip340_test_vectors::test_vectors().into_iter().enumerate() {
            let expected_public_key = test_vector.pubkey;
            let public_key = PublicKey::try_new(*expected_public_key.value()).unwrap();
            assert_eq!(public_key, expected_public_key, "Failed on test vector {i}");
        }
    }

    #[test]
    fn public_key_generation_from_bip340_test_vectors() {
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
    fn correct_ser_deser_roundtrip() {
        let pub_key = PublicKey::try_new([42; 32]).unwrap();

        let pub_key_borsh_ser = borsh::to_vec(&pub_key).unwrap();
        let pub_key_new: PublicKey = borsh::from_slice(&pub_key_borsh_ser).unwrap();

        assert_eq!(pub_key, pub_key_new);
    }
}
