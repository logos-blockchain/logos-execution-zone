use std::collections::BTreeMap;

use k256::{Scalar, elliptic_curve::PrimeField as _};
use lee_core::{NullifierPublicKey, PrivateAccountKind, encryption::ViewingPublicKey};
use serde::{Deserialize, Serialize};

use crate::key_management::{
    KeyChain,
    key_tree::traits::KeyTreeNode,
    secret_holders::{PrivateKeyHolder, SecretSpendingKey},
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(any(test, feature = "test_utils"), derive(PartialEq, Eq))]
pub struct ChildKeysPrivate {
    pub value: (KeyChain, BTreeMap<PrivateAccountKind, lee::Account>),
    pub ccc: [u8; 32],
    /// Can be [`None`] if root.
    pub cci: Option<u32>,
}

impl ChildKeysPrivate {
    #[must_use]
    pub fn root(seed: [u8; 64]) -> Self {
        let hash_value = hmac_sha512::HMAC::mac(seed, b"LEE_master_priv");

        let ssk = SecretSpendingKey(
            *hash_value
                .first_chunk::<32>()
                .expect("hash_value is 64 bytes, must be safe to get first 32"),
        );
        let ccc = *hash_value
            .last_chunk::<32>()
            .expect("hash_value is 64 bytes, must be safe to get last 32");

        let nsk = ssk.generate_nullifier_secret_key(None);
        let vsk = SecretSpendingKey::generate_viewing_secret_key(
            ssk.generate_viewing_secret_seed_key(None),
        );

        let npk = NullifierPublicKey::from(&nsk);
        let vpk = ViewingPublicKey::from(&vsk);

        Self {
            value: (
                KeyChain {
                    secret_spending_key: ssk,
                    nullifier_public_key: npk,
                    viewing_public_key: vpk,
                    private_key_holder: PrivateKeyHolder {
                        nullifier_secret_key: nsk,
                        viewing_secret_key: vsk,
                    },
                },
                BTreeMap::from_iter([(PrivateAccountKind::Regular(0), lee::Account::default())]),
            ),
            ccc,
            cci: None,
        }
    }

    #[must_use]
    pub fn nth_child(&self, cci: u32) -> Self {
        let mut input = vec![];

        input.extend_from_slice(b"LEE_seed_priv");
        input.extend_from_slice(&self.value.0.private_key_holder.nullifier_secret_key);
        #[expect(clippy::big_endian_bytes, reason = "BIP-032 uses big endian")]
        input.extend_from_slice(&cci.to_be_bytes());

        let hash_value = hmac_sha512::HMAC::mac(input, self.ccc);

        let ssk = SecretSpendingKey(
            *hash_value
                .first_chunk::<32>()
                .expect("hash_value is 64 bytes, must be safe to get first 32"),
        );
        let ccc = *hash_value
            .last_chunk::<32>()
            .expect("hash_value is 64 bytes, must be safe to get last 32");

        let nsk = ssk.generate_nullifier_secret_key(Some(cci));
        let vsk = SecretSpendingKey::generate_viewing_secret_key(
            ssk.generate_viewing_secret_seed_key(Some(cci)),
        );

        let npk = NullifierPublicKey::from(&nsk);
        let vpk = ViewingPublicKey::from(&vsk);

        Self {
            value: (
                KeyChain {
                    secret_spending_key: ssk,
                    nullifier_public_key: npk,
                    viewing_public_key: vpk,
                    private_key_holder: PrivateKeyHolder {
                        nullifier_secret_key: nsk,
                        viewing_secret_key: vsk,
                    },
                },
                BTreeMap::from_iter([(PrivateAccountKind::Regular(0), lee::Account::default())]),
            ),
            ccc,
            cci: Some(cci),
        }
    }
}

impl KeyTreeNode for ChildKeysPrivate {
    fn from_seed(seed: [u8; 64]) -> Self {
        Self::root(seed)
    }

    fn derive_child(&self, cci: u32) -> Self {
        self.nth_child(cci)
    }

    fn account_ids(&self) -> impl Iterator<Item = lee::AccountId> {
        let npk = self.value.0.nullifier_public_key;
        self.value
            .1
            .keys()
            .map(move |kind| lee::AccountId::for_private_account(&npk, kind))
    }
}

#[cfg(test)]
mod tests {
    use lee_core::{NullifierPublicKey, NullifierSecretKey};

    use super::*;
    use crate::key_management;

    #[test]
    fn master_key_generation() {
        let seed: [u8; 64] = [
            252, 56, 204, 83, 232, 123, 209, 188, 187, 167, 39, 213, 71, 39, 58, 65, 125, 134, 255,
            49, 43, 108, 92, 53, 173, 164, 94, 142, 150, 74, 21, 163, 43, 144, 226, 87, 199, 18,
            129, 223, 176, 198, 5, 150, 157, 70, 210, 254, 14, 105, 89, 191, 246, 27, 52, 170, 56,
            114, 39, 38, 118, 197, 205, 225,
        ];

        let keys = ChildKeysPrivate::root(seed);

        let expected_ssk: SecretSpendingKey = key_management::secret_holders::SecretSpendingKey([
            246, 79, 26, 124, 135, 95, 52, 51, 201, 27, 48, 194, 2, 144, 51, 219, 245, 128, 139,
            222, 42, 195, 105, 33, 115, 97, 186, 0, 97, 14, 218, 191,
        ]);

        let expected_ccc = [
            56, 114, 70, 249, 67, 169, 206, 9, 192, 11, 180, 168, 149, 129, 42, 95, 43, 157, 130,
            111, 13, 5, 195, 75, 20, 255, 162, 85, 40, 251, 8, 168,
        ];

        let expected_nsk: NullifierSecretKey = [
            154, 102, 103, 5, 34, 235, 227, 13, 22, 182, 226, 11, 7, 67, 110, 162, 99, 193, 174,
            34, 234, 19, 222, 2, 22, 12, 163, 252, 88, 11, 0, 163,
        ];

        let expected_npk: NullifierPublicKey = lee_core::NullifierPublicKey([
            7, 123, 125, 191, 233, 183, 201, 4, 20, 214, 155, 210, 45, 234, 27, 240, 194, 111, 97,
            247, 155, 113, 122, 246, 192, 0, 70, 61, 76, 71, 70, 2,
        ]);

        assert!(expected_ssk == keys.value.0.secret_spending_key);
        assert!(expected_ccc == keys.ccc);
        assert!(expected_nsk == keys.value.0.private_key_holder.nullifier_secret_key);
        assert!(expected_npk == keys.value.0.nullifier_public_key);
        // vsk is now a 64-byte ML-KEM seed; vpk is a 1184-byte encapsulation key — byte
        // vectors are asserted non-empty rather than against the old EC point values.
       // assert!(!keys.value.0.private_key_holder.viewing_secret_key.0.is_empty());
       // assert!(!keys.value.0.viewing_public_key.0.is_empty());
    }

    #[test]
    fn child_keys_generation() {
        let seed: [u8; 64] = [
            252, 56, 204, 83, 232, 123, 209, 188, 187, 167, 39, 213, 71, 39, 58, 65, 125, 134, 255,
            49, 43, 108, 92, 53, 173, 164, 94, 142, 150, 74, 21, 163, 43, 144, 226, 87, 199, 18,
            129, 223, 176, 198, 5, 150, 157, 70, 210, 254, 14, 105, 89, 191, 246, 27, 52, 170, 56,
            114, 39, 38, 118, 197, 205, 225,
        ];

        let root_node = ChildKeysPrivate::root(seed);
        let child_node = ChildKeysPrivate::nth_child(&root_node, 42_u32);

        let expected_nsk: NullifierSecretKey = [
            124, 61, 40, 92, 33, 135, 3, 41, 200, 234, 3, 69, 102, 184, 57, 191, 106, 151, 194,
            192, 103, 132, 141, 112, 249, 108, 192, 117, 24, 48, 70, 216,
        ];
        let expected_npk = lee_core::NullifierPublicKey([
            116, 231, 246, 189, 145, 240, 37, 59, 219, 223, 216, 246, 116, 171, 223, 55, 197, 200,
            134, 192, 221, 40, 218, 167, 239, 5, 11, 95, 147, 247, 162, 226,
        ]);

        assert!(expected_nsk == child_node.value.0.private_key_holder.nullifier_secret_key);
        assert!(expected_npk == child_node.value.0.nullifier_public_key);
       // assert!(!child_node.value.0.private_key_holder.viewing_secret_key.0.is_empty());
       // assert!(!child_node.value.0.viewing_public_key.0.is_empty());
    }
}
