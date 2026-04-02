use bip39::Mnemonic;
use common::HashType;
use nssa_core::{
    NullifierPublicKey, NullifierSecretKey,
    encryption::{Scalar, ViewingPublicKey},
};
use rand::{RngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, digest::FixedOutput as _};

const NSSA_ENTROPY_BYTES: [u8; 32] = [0; 32];

/// Seed holder. Non-clonable to ensure that different holders use different seeds.
/// Produces `TopSecretKeyHolder` objects.
#[derive(Debug)]
pub struct SeedHolder {
    // ToDo: Needs to be vec as serde derives is not implemented for [u8; 64]
    pub(crate) seed: Vec<u8>,
}

/// Secret spending key object. Can produce `PrivateKeyHolder` objects.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SecretSpendingKey(pub [u8; 32]);

pub type ViewingSecretKey = Scalar;

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Private key holder. Produces public keys. Can produce `account_id`. Can produce shared secret
/// for recepient.
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
    pub fn new_mnemonic(passphrase: String) -> Self {
        let mnemonic = Mnemonic::from_entropy(&NSSA_ENTROPY_BYTES)
            .expect("Enthropy must be a multiple of 32 bytes");
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
    fn two_seeds_generated_same_from_same_mnemonic() {
        let mnemonic = "test_pass";

        let seed_holder1 = SeedHolder::new_mnemonic(mnemonic.to_owned());
        let seed_holder2 = SeedHolder::new_mnemonic(mnemonic.to_owned());

        assert_eq!(seed_holder1.seed, seed_holder2.seed);
    }
}
