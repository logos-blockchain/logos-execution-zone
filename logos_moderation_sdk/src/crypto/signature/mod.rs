pub use private_key::PrivateKey;
pub use public_key::PublicKey;
use rand::{RngCore as _, rngs::OsRng};

pub mod private_key;
pub mod public_key;

#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    pub value: [u8; 64],
}

impl Signature {
    #[must_use]
    pub fn new(key: &PrivateKey, message: &[u8]) -> Self {
        let mut aux_random = [0_u8; 32];
        OsRng.fill_bytes(&mut aux_random);
        Self::new_with_aux_random(key, message, aux_random)
    }

    pub(crate) fn new_with_aux_random(
        key: &PrivateKey,
        message: &[u8],
        aux_random: [u8; 32],
    ) -> Self {
        let value = {
            let signing_key = k256::schnorr::SigningKey::from_bytes(key.value())
                .expect("Expect valid signing key");
            signing_key
                .sign_raw(message, &aux_random)
                .expect("Expect to produce a valid signature")
                .to_bytes()
        };

        Self { value }
    }

    #[must_use]
    pub fn is_valid_for(&self, bytes: &[u8], public_key: &PublicKey) -> bool {
        let Ok(pk) = k256::schnorr::VerifyingKey::from_bytes(public_key.value()) else {
            return false;
        };

        let Ok(sig) = k256::schnorr::Signature::try_from(self.value.as_slice()) else {
            return false;
        };

        pk.verify_raw(bytes, &sig).is_ok()
    }
}