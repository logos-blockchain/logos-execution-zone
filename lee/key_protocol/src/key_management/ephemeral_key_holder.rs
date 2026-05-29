use lee_core::{
    SharedSecretKey,
    encryption::{EphemeralPublicKey, ViewingPublicKey},
};

/// Ephemeral key holder for the sender side of a KEM-based shared-secret exchange.
///
/// Non-clonable as intended for one-time use: construction encapsulates once and
/// stores both the shared secret and the ciphertext (`EphemeralPublicKey`) that must
/// be sent to the receiver.
pub struct EphemeralKeyHolder {
    shared_secret: SharedSecretKey,
    ephemeral_public_key: EphemeralPublicKey,
}

// SharedSecretKey does not implement Debug (intentional — leaking key material via
// debug output would be a security risk). We implement Debug manually here, redacting the
// shared secret while still allowing the ephemeral public key (KEM ciphertext) to be inspected.
impl std::fmt::Debug for EphemeralKeyHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralKeyHolder")
            .field("shared_secret", &"<redacted>")
            .field("ephemeral_public_key", &self.ephemeral_public_key)
            .finish()
    }
}

impl EphemeralKeyHolder {
    #[must_use]
    pub fn new(receiver_viewing_public_key: &ViewingPublicKey) -> Self {
        let (shared_secret, ephemeral_public_key) =
            SharedSecretKey::encapsulate(receiver_viewing_public_key);
        Self {
            shared_secret,
            ephemeral_public_key,
        }
    }

    /// Returns the KEM ciphertext to be transmitted to the receiver as the `EphemeralPublicKey`.
    #[must_use]
    pub const fn ephemeral_public_key(&self) -> &EphemeralPublicKey {
        &self.ephemeral_public_key
    }

    /// Returns the sender-side shared secret (established at construction time).
    #[must_use]
    pub const fn calculate_shared_secret_sender(&self) -> SharedSecretKey {
        self.shared_secret
    }
}

/// Encapsulates a fresh shared secret toward `vpk` and returns `(shared_secret, ciphertext)`.
///
/// Used when the local side is acting as an "ephemeral receiver" — i.e. generating a
/// one-sided encryption that only the holder of the VSK can decrypt.
#[must_use]
pub fn produce_one_sided_shared_secret_receiver(
    vpk: &ViewingPublicKey,
) -> (SharedSecretKey, EphemeralPublicKey) {
    SharedSecretKey::encapsulate(vpk)
}
