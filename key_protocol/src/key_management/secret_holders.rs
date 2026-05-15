use bip39::Mnemonic;
use common::HashType;
use nssa_core::{
    NullifierPublicKey, NullifierSecretKey,
    encryption::{Scalar, ViewingPublicKey},
};
use rand::{RngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, digest::FixedOutput as _};

/// Seed holder. Non-clonable to ensure that different holders use different seeds.
/// Produces `TopSecretKeyHolder` objects.
#[derive(Debug)]
pub struct SeedHolder {
    // ToDo: Needs to be vec as serde derives is not implemented for [u8; 64]
    pub(crate) seed: Vec<u8>,
}

/// Secret spending key object. Can produce `PrivateKeyHolder` objects.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecretSpendingKey(pub [u8; 32]);

pub type ViewingSecretKey = Scalar;

/// Private key holder. Produces public keys. Can produce `account_id`. Can produce shared secret
/// for recepient.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrivateKeyHolder {
    pub nullifier_secret_key: NullifierSecretKey,
    pub viewing_secret_key: ViewingSecretKey,
}

impl SeedHolder {
    #[must_use]
    pub fn new_os_random() -> Self {
        let mut enthopy_bytes: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut enthopy_bytes);

        let mnemonic = Mnemonic::from_entropy(&enthopy_bytes)
            .expect("Enthropy must be a multiple of 32 bytes");
        let seed_wide = mnemonic.to_seed("mnemonic");

        Self {
            seed: seed_wide.to_vec(),
        }
    }

    #[must_use]
    pub fn new_mnemonic(passphrase: &str) -> (Self, Mnemonic) {
        let mut entropy_bytes: [u8; 32] = [0; 32];
        OsRng.fill_bytes(&mut entropy_bytes);

        let mnemonic =
            Mnemonic::from_entropy(&entropy_bytes).expect("Entropy must be a multiple of 32 bytes");
        let seed_wide = mnemonic.to_seed(passphrase);

        (
            Self {
                seed: seed_wide.to_vec(),
            },
            mnemonic,
        )
    }

    #[must_use]
    pub fn from_mnemonic(mnemonic: &Mnemonic, passphrase: &str) -> Self {
        let seed_wide = mnemonic.to_seed(passphrase);

        Self {
            seed: seed_wide.to_vec(),
        }
    }

    #[must_use]
    pub fn generate_secret_spending_key_hash(&self) -> HashType {
        let mut hash = hmac_sha512::HMAC::mac(&self.seed, "NSSA_seed");

        for _ in 1..2048 {
            hash = hmac_sha512::HMAC::mac(hash, "NSSA_seed");
        }

        // Safe unwrap
        HashType(*hash.first_chunk::<32>().unwrap())
    }

    #[must_use]
    pub fn produce_top_secret_key_holder(&self) -> SecretSpendingKey {
        SecretSpendingKey(self.generate_secret_spending_key_hash().into())
    }
}

impl SecretSpendingKey {
    #[must_use]
    #[expect(clippy::big_endian_bytes, reason = "BIP-032 uses big endian")]
    pub fn generate_nullifier_secret_key(&self, index: Option<u32>) -> NullifierSecretKey {
        const PREFIX: &[u8; 8] = b"LEE/keys";
        const SUFFIX_1: &[u8; 1] = &[1];
        const SUFFIX_2: &[u8; 19] = &[0; 19];

        let index = match index {
            None => 0_u32,
            _ => index.expect("Expect a valid u32"),
        };

        let mut hasher = sha2::Sha256::new();
        hasher.update(PREFIX);
        hasher.update(self.0);
        hasher.update(SUFFIX_1);
        hasher.update(index.to_be_bytes());
        hasher.update(SUFFIX_2);

        <NullifierSecretKey>::from(hasher.finalize_fixed())
    }

    #[must_use]
    #[expect(clippy::big_endian_bytes, reason = "BIP-032 uses big endian")]
    pub fn generate_viewing_secret_key(&self, index: Option<u32>) -> ViewingSecretKey {
        const PREFIX: &[u8; 8] = b"LEE/keys";
        const SUFFIX_1: &[u8; 1] = &[2];
        const SUFFIX_2: &[u8; 19] = &[0; 19];

        let index = match index {
            None => 0_u32,
            _ => index.expect("Expect a valid u32"),
        };

        let mut hasher = sha2::Sha256::new();
        hasher.update(PREFIX);
        hasher.update(self.0);
        hasher.update(SUFFIX_1);
        hasher.update(index.to_be_bytes());
        hasher.update(SUFFIX_2);

        hasher.finalize_fixed().into()
    }

    #[must_use]
    pub fn produce_private_key_holder(&self, index: Option<u32>) -> PrivateKeyHolder {
        PrivateKeyHolder {
            nullifier_secret_key: self.generate_nullifier_secret_key(index),
            viewing_secret_key: self.generate_viewing_secret_key(index),
        }
    }
}

impl PrivateKeyHolder {
    #[must_use]
    pub fn generate_nullifier_public_key(&self) -> NullifierPublicKey {
        (&self.nullifier_secret_key).into()
    }

    #[must_use]
    pub fn generate_viewing_public_key(&self) -> ViewingPublicKey {
        ViewingPublicKey::from_scalar(self.viewing_secret_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO? are these necessary?
    #[test]
    fn seed_generation_test() {
        let seed_holder = SeedHolder::new_os_random();

        assert_eq!(seed_holder.seed.len(), 64);
    }

    #[test]
    fn ssk_generation_test() {
        let seed_holder = SeedHolder::new_os_random();

        assert_eq!(seed_holder.seed.len(), 64);

        let _hash = seed_holder.generate_secret_spending_key_hash();
    }

    #[test]
    fn ivs_generation_test() {
        let seed_holder = SeedHolder::new_os_random();

        assert_eq!(seed_holder.seed.len(), 64);

        let top_secret_key_holder = seed_holder.produce_top_secret_key_holder();

        let _vsk = top_secret_key_holder.generate_viewing_secret_key(None);
    }

    #[test]
    fn two_seeds_recovered_same_from_same_mnemonic() {
        let passphrase = "test_pass";

        // Generate a mnemonic with random entropy
        let (original_seed_holder, mnemonic) = SeedHolder::new_mnemonic(passphrase);

        // Recover from the same mnemonic
        let recovered_seed_holder = SeedHolder::from_mnemonic(&mnemonic, passphrase);

        assert_eq!(original_seed_holder.seed, recovered_seed_holder.seed);
    }

    #[test]
    fn new_mnemonic_generates_different_seeds_each_time() {
        let (seed_holder1, mnemonic1) = SeedHolder::new_mnemonic("");
        let (seed_holder2, mnemonic2) = SeedHolder::new_mnemonic("");

        // Different entropy should produce different mnemonics and seeds
        assert_ne!(mnemonic1.to_string(), mnemonic2.to_string());
        assert_ne!(seed_holder1.seed, seed_holder2.seed);
    }

    #[test]
    fn new_mnemonic_generates_24_word_phrase() {
        let (_seed_holder, mnemonic) = SeedHolder::new_mnemonic("");

        // 256 bits of entropy produces a 24-word mnemonic
        let word_count = mnemonic.to_string().split_whitespace().count();
        assert_eq!(word_count, 24);
    }

    #[test]
    fn new_mnemonic_produces_valid_seed_length() {
        let (seed_holder, _mnemonic) = SeedHolder::new_mnemonic("");

        assert_eq!(seed_holder.seed.len(), 64);
    }

    #[test]
    fn different_passphrases_produce_different_seeds() {
        let (_seed_holder, mnemonic) = SeedHolder::new_mnemonic("");

        let seed_with_pass_a = SeedHolder::from_mnemonic(&mnemonic, "password_a");
        let seed_with_pass_b = SeedHolder::from_mnemonic(&mnemonic, "password_b");

        // Same mnemonic but different passphrases should produce different seeds
        assert_ne!(seed_with_pass_a.seed, seed_with_pass_b.seed);
    }

    #[test]
    fn empty_passphrase_is_deterministic() {
        let (_seed_holder, mnemonic) = SeedHolder::new_mnemonic("");

        let seed1 = SeedHolder::from_mnemonic(&mnemonic, "");
        let seed2 = SeedHolder::from_mnemonic(&mnemonic, "");

        // Same mnemonic and passphrase should always produce the same seed
        assert_eq!(seed1.seed, seed2.seed);
    }
}
