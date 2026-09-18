use k256::elliptic_curve::PrimeField as _;
use serde::{Deserialize, Serialize};

use crate::key_management::key_tree::{split_hash, traits::KeyTreeNode};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(any(test, feature = "test_utils"), derive(PartialEq, Eq))]
pub struct ChildKeysPublic {
    /// Secret key for public account.
    pub sk: lee::PrivateKey,
    /// Schnorr secret key.
    pub ssk: lee::PrivateKey,
    /// Schnorr public key.
    pub pk: lee::PublicKey,
    pub cc: [u8; 32],
    /// Can be [`None`] if root.
    pub cci: Option<u32>,
}

impl ChildKeysPublic {
    #[must_use]
    pub fn root(seed: [u8; 64]) -> Self {
        let hash_value = hmac_sha512::HMAC::mac(seed, "/LEE-Keys/v1/Master/Public");
        let (first, cc) = split_hash(&hash_value);

        let sk = lee::PrivateKey::try_new(first).expect("Expect a valid Private Key");

        Self::from_sk_and_cc(sk, cc, None)
    }

    #[must_use]
    pub fn nth_child(&self, cci: u32) -> Self {
        let hash_value = self.compute_hash_value(cci);
        let (first, cc) = split_hash(&hash_value);

        let lhs = k256::Scalar::from_repr(first.into()).expect("Expect a valid k256 scalar");
        let rhs =
            k256::Scalar::from_repr((*self.sk.value()).into()).expect("Expect a valid k256 scalar");

        let sk = lee::PrivateKey::try_new(lhs.add(&rhs).to_bytes().into())
            .expect("Expect a valid private key");

        Self::from_sk_and_cc(sk, cc, Some(cci))
    }

    fn from_sk_and_cc(sk: lee::PrivateKey, cc: [u8; 32], cci: Option<u32>) -> Self {
        let ssk = lee::PrivateKey::tweak(sk.value()).expect(
            "`key_protocol::key_management::keys_public::ChildKeysPublic`: Invalid private key produced from `tweak`",
        );
        let pk = lee::PublicKey::new_from_private_key(&ssk);

        Self {
            sk,
            ssk,
            pk,
            cc,
            cci,
        }
    }

    #[must_use]
    pub fn account_id(&self) -> lee::AccountId {
        lee::AccountId::from(&self.pk)
    }

    fn compute_hash_value(&self, cci: u32) -> [u8; 64] {
        let mut hash_input = vec![];
        // Simplified key logic by only supporting harden keys.
        // Non-harden keys would require access to untweaked public keys associated to `sk`s.
        // Thus, not PQ secure.
        hash_input.extend_from_slice(&[0_u8]);
        hash_input.extend_from_slice(self.sk.value());

        #[expect(clippy::big_endian_bytes, reason = "BIP-032 uses big endian")]
        hash_input.extend_from_slice(&cci.to_be_bytes());

        hmac_sha512::HMAC::mac(hash_input, self.cc)
    }
}

#[expect(
    clippy::single_char_lifetime_names,
    reason = "TODO add meaningful name"
)]
impl<'a> From<&'a ChildKeysPublic> for &'a lee::PrivateKey {
    fn from(value: &'a ChildKeysPublic) -> Self {
        &value.ssk
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
    use lee::{PrivateKey, PublicKey};

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

        let expected_cc = [
            184, 94, 197, 114, 84, 79, 170, 62, 107, 107, 141, 196, 11, 255, 15, 165, 7, 40, 93,
            211, 244, 153, 12, 70, 10, 174, 141, 69, 117, 167, 165, 81,
        ];

        let expected_sk: PrivateKey = PrivateKey::try_new([
            142, 140, 44, 81, 255, 159, 131, 163, 210, 67, 198, 176, 43, 243, 163, 35, 242, 200,
            232, 99, 69, 240, 63, 16, 33, 104, 8, 152, 243, 153, 180, 169,
        ])
        .unwrap();

        let expected_ssk: PrivateKey = PrivateKey::try_new([
            241, 47, 167, 208, 182, 77, 106, 158, 182, 41, 17, 3, 91, 229, 165, 35, 90, 33, 145,
            202, 246, 65, 127, 65, 124, 240, 165, 152, 127, 50, 60, 198,
        ])
        .unwrap();

        let expected_pk: PublicKey = PublicKey::try_new([
            43, 138, 92, 79, 223, 49, 90, 162, 205, 76, 143, 151, 96, 77, 10, 85, 179, 208, 244,
            71, 251, 191, 237, 226, 120, 247, 194, 57, 117, 180, 96, 65,
        ])
        .unwrap();

        assert!(expected_cc == keys.cc);
        assert!(expected_ssk == keys.ssk);
        assert!(expected_sk == keys.sk);
        assert!(expected_pk == keys.pk);
    }

    #[test]
    fn child_keys_generation() {
        let root_keys = ChildKeysPublic::root(SEED);
        let cci = (2_u32).pow(31) + 13;
        let child_keys = ChildKeysPublic::nth_child(&root_keys, cci);

        let expected_cc = [
            184, 162, 65, 125, 129, 202, 96, 126, 157, 15, 189, 122, 22, 152, 31, 107, 244, 188,
            215, 30, 70, 205, 164, 142, 6, 152, 106, 147, 160, 1, 168, 168,
        ];

        let expected_sk: PrivateKey = PrivateKey::try_new([
            222, 78, 224, 138, 167, 32, 235, 208, 192, 129, 121, 150, 204, 149, 151, 33, 82, 109,
            238, 245, 20, 106, 70, 126, 120, 66, 165, 169, 241, 242, 224, 10,
        ])
        .unwrap();

        let expected_ssk: PrivateKey = PrivateKey::try_new([
            103, 101, 18, 63, 86, 198, 110, 120, 163, 160, 181, 249, 184, 163, 7, 38, 132, 223, 72,
            208, 74, 223, 16, 110, 60, 227, 167, 192, 89, 28, 14, 222,
        ])
        .unwrap();

        let expected_pk: PublicKey = PublicKey::try_new([
            107, 153, 105, 58, 6, 157, 131, 253, 141, 130, 168, 182, 82, 2, 99, 26, 211, 22, 55,
            203, 23, 34, 236, 147, 86, 156, 194, 114, 89, 77, 219, 173,
        ])
        .unwrap();

        assert!(expected_cc == child_keys.cc);
        assert!(expected_ssk == child_keys.ssk);
        assert!(expected_sk == child_keys.sk);
        assert!(expected_pk == child_keys.pk);
    }
}
