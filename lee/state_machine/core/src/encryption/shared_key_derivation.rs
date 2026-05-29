use borsh::{BorshDeserialize, BorshSerialize};
use ml_kem::{Decapsulate as _, Encapsulate as _, KeyExport as _, Seed};
use serde::{Deserialize, Serialize};

use crate::SharedSecretKey;

/// The ML-KEM-768 ciphertext produced during encapsulation; transmitted on-wire in place of the
/// former ECDH ephemeral public key.  Always 1088 bytes for ML-KEM-768.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EphemeralPublicKey(pub Vec<u8>);

/// ML-KEM-768 encapsulation key bytes (1184 bytes, opaque to this crate).
#[derive(
    Serialize,
    Deserialize,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct ViewingPublicKey(pub Vec<u8>);

impl ViewingPublicKey {
    #[must_use]
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Derive the ML-KEM-768 encapsulation key from the FIPS 203 seed halves `d` and `z`.
    /// Allows any crate to construct a VPK from raw seed bytes without importing
    /// `key_protocol::ViewingSecretKey`.
    #[must_use]
    pub fn from_seed(d: &[u8; 32], z: &[u8; 32]) -> Self {
        let mut seed = Seed::default();
        seed[..32].copy_from_slice(d);
        seed[32..].copy_from_slice(z);
        let dk = ml_kem::DecapsulationKey768::from_seed(seed);
        Self(dk.encapsulation_key().to_bytes().to_vec())
    }
}

impl SharedSecretKey {
    /// Sender: encapsulate a fresh shared secret toward `vpk`.
    ///
    /// Returns `(shared_secret, ciphertext)`.  The ciphertext must be included in the transaction
    /// as the `EphemeralPublicKey`; the receiver recovers the same shared secret via
    /// [`decapsulate`][Self::decapsulate].
    #[must_use]
    pub fn encapsulate(vpk: &ViewingPublicKey) -> (Self, EphemeralPublicKey) {
        let ek_bytes: ml_kem::kem::Key<ml_kem::EncapsulationKey768> = vpk
            .0
            .as_slice()
            .try_into()
            .expect("ViewingPublicKey must be 1184 bytes (ML-KEM-768 encapsulation key)");
        let ek = ml_kem::EncapsulationKey768::new(&ek_bytes)
            .expect("ViewingPublicKey bytes must encode a valid ML-KEM-768 encapsulation key");
        let (ct, ss) = ek.encapsulate();
        let ss_bytes: [u8; 32] = ss
            .as_slice()
            .try_into()
            .expect("ML-KEM shared key is 32 bytes");
        (Self(ss_bytes), EphemeralPublicKey(ct.to_vec()))
    }

    /// Sender: deterministically encapsulate a shared secret toward `vpk`.
    ///
    /// The KEM randomness is derived as `SHA-256(message_hash || output_index_le)`,
    /// making the ciphertext reproducible from the same `(vpk, message_hash, output_index)`
    /// triple. Use a distinct `output_index` for each private account output in the same
    /// transaction to ensure per-output EPK uniqueness.
    #[must_use]
    pub fn encapsulate_deterministic(
        vpk: &ViewingPublicKey,
        message_hash: &[u8; 32],
        output_index: u32,
    ) -> (Self, EphemeralPublicKey) {
        use risc0_zkvm::sha::{Impl, Sha256 as _};

        let mut input = Vec::with_capacity(36);
        input.extend_from_slice(message_hash);
        input.extend_from_slice(&output_index.to_le_bytes());
        let hash = Impl::hash_bytes(&input);
        let m: ml_kem::B32 =
            ml_kem::array::Array::try_from(hash.as_bytes()).expect("SHA-256 output is 32 bytes");

        let ek_bytes: ml_kem::kem::Key<ml_kem::EncapsulationKey768> = vpk
            .0
            .as_slice()
            .try_into()
            .expect("ViewingPublicKey must be 1184 bytes (ML-KEM-768 encapsulation key)");
        let ek = ml_kem::EncapsulationKey768::new(&ek_bytes)
            .expect("ViewingPublicKey bytes must encode a valid ML-KEM-768 encapsulation key");
        let (ct, ss) = ek.encapsulate_deterministic(&m);
        let ss_bytes: [u8; 32] = ss
            .as_slice()
            .try_into()
            .expect("ML-KEM shared key is 32 bytes");
        (Self(ss_bytes), EphemeralPublicKey(ct.to_vec()))
    }

    /// Receiver: decapsulate the shared secret from a KEM ciphertext.
    ///
    /// Returns `None` if the `EphemeralPublicKey` is not exactly 1088 bytes — callers on
    /// the wallet scan path should skip the output rather than panic on malformed chain data.
    ///
    /// `d` and `z` are the two 32-byte halves of the FIPS 203 `ViewingSecretKey` seed.
    #[must_use]
    pub fn decapsulate(ciphertext: &EphemeralPublicKey, d: &[u8; 32], z: &[u8; 32]) -> Option<Self> {
        let mut seed = Seed::default();
        seed[..32].copy_from_slice(d);
        seed[32..].copy_from_slice(z);
        let dk = ml_kem::DecapsulationKey768::from_seed(seed);
        let ss = dk.decapsulate_slice(&ciphertext.0).ok()?;
        let ss_bytes: [u8; 32] = ss
            .as_slice()
            .try_into()
            .expect("ML-KEM shared key is 32 bytes");
        Some(Self(ss_bytes))
    }
}

#[cfg(test)]
mod tests {
    use ml_kem::KeyExport as _;

    use super::*;

    #[test]
    fn encapsulate_decapsulate_round_trip() {
        let d = [1_u8; 32];
        let z = [2_u8; 32];

        let mut seed = Seed::default();
        seed[..32].copy_from_slice(&d);
        seed[32..].copy_from_slice(&z);

        let dk = ml_kem::DecapsulationKey768::from_seed(seed);
        let ek_bytes = dk.encapsulation_key().to_bytes();
        let vpk = ViewingPublicKey(ek_bytes.to_vec());

        let (sender_ss, epk) = SharedSecretKey::encapsulate(&vpk);
        let receiver_ss = SharedSecretKey::decapsulate(&epk, &d, &z).unwrap();

        assert_eq!(sender_ss.0, receiver_ss.0, "shared secrets must match");
        assert_eq!(epk.0.len(), 1088, "ML-KEM-768 ciphertext is 1088 bytes");
        assert_eq!(
            vpk.0.len(),
            1184,
            "ML-KEM-768 encapsulation key is 1184 bytes"
        );
    }

    #[test]
    fn decapsulate_returns_none_for_malformed_epk() {
        let d = [1_u8; 32];
        let z = [2_u8; 32];

        // Too short — 100 bytes instead of 1088.
        let short_epk = EphemeralPublicKey(vec![42_u8; 100]);
        assert!(
            SharedSecretKey::decapsulate(&short_epk, &d, &z).is_none(),
            "short EphemeralPublicKey must return None"
        );

        // Too long — 1089 bytes instead of 1088.
        let long_epk = EphemeralPublicKey(vec![42_u8; 1089]);
        assert!(
            SharedSecretKey::decapsulate(&long_epk, &d, &z).is_none(),
            "long EphemeralPublicKey must return None"
        );

        // Empty.
        let empty_epk = EphemeralPublicKey(vec![]);
        assert!(
            SharedSecretKey::decapsulate(&empty_epk, &d, &z).is_none(),
            "empty EphemeralPublicKey must return None"
        );
    }

    #[test]
    fn different_vpks_produce_different_shared_secrets() {
        let (d1, z1) = ([1_u8; 32], [2_u8; 32]);
        let (d2, z2) = ([3_u8; 32], [4_u8; 32]);

        let vpk1 = {
            let mut seed = Seed::default();
            seed[..32].copy_from_slice(&d1);
            seed[32..].copy_from_slice(&z1);
            let dk = ml_kem::DecapsulationKey768::from_seed(seed);
            ViewingPublicKey(dk.encapsulation_key().to_bytes().to_vec())
        };
        let vpk2 = {
            let mut seed = Seed::default();
            seed[..32].copy_from_slice(&d2);
            seed[32..].copy_from_slice(&z2);
            let dk = ml_kem::DecapsulationKey768::from_seed(seed);
            ViewingPublicKey(dk.encapsulation_key().to_bytes().to_vec())
        };

        let (ss1, _) = SharedSecretKey::encapsulate(&vpk1);
        let (ss2, _) = SharedSecretKey::encapsulate(&vpk2);

        assert_ne!(ss1.0, ss2.0);
    }
}
