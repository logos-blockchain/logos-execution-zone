use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use crate::crypto::signature::PrivateKey;

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

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

    pub fn try_new(value: [u8; 32]) -> Result<Self, &'static str> {
        let _ = k256::schnorr::VerifyingKey::from_bytes(&value).map_err(|_| "InvalidPublicKey")?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn value(&self) -> &[u8; 32] {
        &self.0
    }
}