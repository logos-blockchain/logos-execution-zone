use lee::signature::{PublicAccountSecret, public_account_id};
use serde::{Deserialize, Serialize};

use crate::key_management::key_tree::{split_hash, traits::KeyTreeNode};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(any(test, feature = "test_utils"), derive(PartialEq, Eq))]
pub struct ChildKeysPublic {
    /// Secret for public account.
    pub secret: PublicAccountSecret,
    /// Can be [`None`] if root.
    pub cci: Option<u32>,
}

impl ChildKeysPublic {
    #[must_use]
    pub fn root(seed: [u8; 64]) -> Self {
        let hash_value = hmac_sha512::HMAC::mac(seed, "/LEE-Keys/v1/Master/Public");
        let (secret, _) = split_hash(&hash_value);

        Self {
            secret: PublicAccountSecret::new(secret),
            cci: None,
        }
    }

    #[must_use]
    pub fn nth_child(&self, cci: u32) -> Self {
        // Simplified key logic by only supporting harden keys.
        #[expect(clippy::big_endian_bytes, reason = "BIP-032 uses big endian")]
        let hash_input = [b"/LEE-Keys/v1/Child/Public".as_slice(), &cci.to_be_bytes()].concat();
        let hash_value = hmac_sha512::HMAC::mac(hash_input, self.secret.value());
        let (secret, _) = split_hash(&hash_value);

        Self {
            secret: PublicAccountSecret::new(secret),
            cci: Some(cci),
        }
    }

    #[must_use]
    pub fn account_id(&self) -> lee::AccountId {
        public_account_id(&self.secret)
    }
}

impl KeyTreeNode for ChildKeysPublic {
    fn from_seed(seed: [u8; 64]) -> Self {
        Self::root(seed)
    }

    fn derive_child(&self, cci: u32) -> Self {
        self.nth_child(cci)
    }

    fn account_ids(&self) -> impl Iterator<Item = lee::AccountId> {
        std::iter::once(self.account_id())
    }
}

#[cfg(test)]
mod tests {
    use lee::signature::{KeyScheme as _, Wots, signing_key};
    use lee_core::account::Nonce;

    use super::*;

    const SEED: [u8; 64] = [
        88, 189, 37, 237, 199, 125, 151, 226, 69, 153, 165, 113, 191, 69, 188, 221, 9, 34, 173,
        134, 61, 109, 34, 103, 121, 39, 237, 14, 107, 194, 24, 194, 191, 14, 237, 185, 12, 87, 22,
        227, 38, 71, 17, 144, 251, 118, 217, 115, 33, 222, 201, 61, 203, 246, 121, 214, 6, 187,
        148, 92, 44, 253, 210, 37,
    ];

    #[test]
    fn master_keys_generation() {
        let keys = ChildKeysPublic::root(SEED);

        let expected_secret = PublicAccountSecret::new([
            142, 140, 44, 81, 255, 159, 131, 163, 210, 67, 198, 176, 43, 243, 163, 35, 242, 200,
            232, 99, 69, 240, 63, 16, 33, 104, 8, 152, 243, 153, 180, 169,
        ]);

        assert_eq!(expected_secret, keys.secret);
    }

    #[test]
    fn child_keys_generation() {
        let root_keys = ChildKeysPublic::root(SEED);
        let cci = (2_u32).pow(31) + 13;
        let child_keys = ChildKeysPublic::nth_child(&root_keys, cci);

        let expected_secret = PublicAccountSecret::new([
            112, 124, 240, 49, 175, 95, 86, 169, 176, 184, 184, 250, 10, 9, 128, 16, 199, 85, 135,
            32, 151, 67, 135, 229, 2, 233, 137, 79, 222, 205, 137, 248,
        ]);

        assert_eq!(expected_secret, child_keys.secret);
    }

    #[test]
    fn account_id_is_that_of_the_nonce_zero_key() {
        let keys = ChildKeysPublic::root(SEED);
        let (_sk_0, pk_0) = signing_key::<Wots>(&keys.secret, Nonce(0));

        assert_eq!(
            Some(keys.account_id()),
            lee::AccountId::for_initial_key(&Wots::key_state(&pk_0))
        );
    }
}
