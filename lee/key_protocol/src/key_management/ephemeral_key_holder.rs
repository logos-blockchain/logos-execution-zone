use lee_core::{
    NullifierPublicKey, SharedSecretKey,
    encryption::{EphemeralPublicKey, EphemeralSecretKey, ViewingPublicKey,
    shared_key_derivation::Secp256k1Point},
};
use rand::{RngCore as _, rngs::OsRng};
use sha2::Digest as _;

#[derive(Debug)]
/// Ephemeral secret key holder. Non-clonable as intended for one-time use. Produces ephemeral
/// public keys. Can produce shared secret for sender.
pub struct EphemeralKeyHolder {
    ephemeral_secret_key: EphemeralSecretKey,
}

impl EphemeralKeyHolder {
    #[must_use]
    pub fn new(receiver_nullifier_public_key: &NullifierPublicKey) -> Self {
        let mut nonce_bytes = [0; 16];
        OsRng.fill_bytes(&mut nonce_bytes);
        let mut hasher = sha2::Sha256::new();
        hasher.update(receiver_nullifier_public_key);
        hasher.update(nonce_bytes);

        Self {
            ephemeral_secret_key: hasher.finalize().into(),
        }
    }

    #[must_use]
    pub fn generate_ephemeral_public_key(&self) -> EphemeralPublicKey {
        EphemeralPublicKey::from_scalar(self.ephemeral_secret_key)
    }

    #[must_use]
    pub fn calculate_shared_secret_sender(
        &self,
        _receiver_viewing_public_key: &ViewingPublicKey,
    ) -> SharedSecretKey {
        SharedSecretKey::new(self.ephemeral_secret_key, &Secp256k1Point::from_scalar(self.ephemeral_secret_key))
    }
}

#[must_use]
pub fn produce_one_sided_shared_secret_receiver(
    _vpk: &ViewingPublicKey,
) -> (SharedSecretKey, EphemeralPublicKey) {
    let mut esk = [0; 32];
    OsRng.fill_bytes(&mut esk);
    (
        SharedSecretKey::new(esk, &Secp256k1Point::from_scalar(esk)),
        EphemeralPublicKey::from_scalar(esk),
    )
}
