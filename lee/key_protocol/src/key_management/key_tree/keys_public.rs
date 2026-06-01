use k256::elliptic_curve::PrimeField as _;
use serde::{Deserialize, Serialize};

use crate::key_management::key_tree::traits::KeyTreeNode;

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
        let hash_value = hmac_sha512::HMAC::mac(seed, "LEE_master_pub");

        let sk = lee::PrivateKey::try_new(
            *hash_value
                .first_chunk::<32>()
                .expect("hash_value is 64 bytes, must be safe to get first 32"),
        )
        .expect("Expect a valid Private Key");
        let ssk = lee::PrivateKey::tweak(sk.value()).expect("`key_protocol::key_management::keys_public::root()`: Invalid private key produced from `tweak`");

        let cc = *hash_value
            .last_chunk::<32>()
            .expect("hash_value is 64 bytes, must be safe to get last 32");
        let pk = lee::PublicKey::new_from_private_key(&ssk);

        Self {
            sk,
            ssk,
            pk,
            cc,
            cci: None,
        }
    }

    #[must_use]
    pub fn nth_child(&self, cci: u32) -> Self {
        let hash_value = self.compute_hash_value(cci);

        let lhs = k256::Scalar::from_repr(
            (*hash_value
                .first_chunk::<32>()
                .expect("hash_value is 64 bytes, must be safe to get first 32"))
            .into(),
        )
        .expect("Expect a valid k256 scalar");
        let rhs =
            k256::Scalar::from_repr((*self.sk.value()).into()).expect("Expect a valid k256 scalar");

        let sk = lee::PrivateKey::try_new(lhs.add(&rhs).to_bytes().into())
            .expect("Expect a valid private key");

        let ssk = lee::PrivateKey::tweak(sk.value()).expect("`key_protocol::key_management::keys_public::nth_child()`: Invalid private key produced from `tweak`");

        let cc = *hash_value
            .last_chunk::<32>()
            .expect("hash_value is 64 bytes, must be safe to get last 32");

        let pk = lee::PublicKey::new_from_private_key(&ssk);

        Self {
            sk,
            ssk,
            pk,
            cc,
            cci: Some(cci),
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

    #[test]
    fn master_keys_generation() {
        let seed = [
            88, 189, 37, 237, 199, 125, 151, 226, 69, 153, 165, 113, 191, 69, 188, 221, 9, 34, 173,
            134, 61, 109, 34, 103, 121, 39, 237, 14, 107, 194, 24, 194, 191, 14, 237, 185, 12, 87,
            22, 227, 38, 71, 17, 144, 251, 118, 217, 115, 33, 222, 201, 61, 203, 246, 121, 214, 6,
            187, 148, 92, 44, 253, 210, 37,
        ];
        let keys = ChildKeysPublic::root(seed);

        let expected_cc = [
            238, 94, 84, 154, 56, 224, 80, 218, 133, 249, 179, 222, 9, 24, 17, 252, 120, 127, 222,
            13, 146, 126, 232, 239, 113, 9, 194, 219, 190, 48, 187, 155,
        ];

        let expected_sk: PrivateKey = PrivateKey::try_new([
            40, 35, 239, 19, 53, 178, 250, 55, 115, 12, 34, 3, 153, 153, 72, 170, 190, 36, 172, 36,
            202, 148, 181, 228, 35, 222, 58, 84, 156, 24, 146, 86,
        ])
        .unwrap();

        let expected_ssk: PrivateKey = PrivateKey::try_new([
            207, 4, 246, 223, 104, 72, 19, 85, 14, 122, 194, 82, 32, 163, 60, 57, 8, 25, 209, 91,
            254, 107, 76, 238, 31, 68, 236, 192, 154, 78, 105, 118,
        ])
        .unwrap();

        let expected_pk: PublicKey = PublicKey::try_new([
            188, 163, 203, 45, 151, 154, 230, 254, 123, 114, 158, 130, 19, 182, 164, 143, 150, 131,
            176, 7, 27, 58, 204, 116, 5, 247, 0, 255, 111, 160, 52, 201,
        ])
        .unwrap();

        assert!(expected_cc == keys.cc);
        assert!(expected_ssk == keys.ssk);
        assert!(expected_sk == keys.sk);
        assert!(expected_pk == keys.pk);
    }

    #[test]
    fn child_keys_generation() {
        let seed = [
            88, 189, 37, 237, 199, 125, 151, 226, 69, 153, 165, 113, 191, 69, 188, 221, 9, 34, 173,
            134, 61, 109, 34, 103, 121, 39, 237, 14, 107, 194, 24, 194, 191, 14, 237, 185, 12, 87,
            22, 227, 38, 71, 17, 144, 251, 118, 217, 115, 33, 222, 201, 61, 203, 246, 121, 214, 6,
            187, 148, 92, 44, 253, 210, 37,
        ];
        let root_keys = ChildKeysPublic::root(seed);
        let cci = (2_u32).pow(31) + 13;
        let child_keys = ChildKeysPublic::nth_child(&root_keys, cci);

        let expected_cc = [
            149, 226, 13, 4, 194, 12, 69, 29, 9, 234, 209, 119, 98, 4, 128, 91, 37, 103, 192, 31,
            130, 126, 123, 20, 90, 34, 173, 209, 101, 248, 155, 36,
        ];

        let expected_sk: PrivateKey = PrivateKey::try_new([
            9, 65, 33, 228, 25, 82, 219, 117, 91, 217, 11, 223, 144, 85, 246, 26, 123, 216, 107,
            213, 33, 52, 188, 22, 198, 246, 71, 46, 245, 174, 16, 47,
        ])
        .unwrap();

        let expected_ssk: PrivateKey = PrivateKey::try_new([
            100, 37, 212, 81, 40, 233, 72, 156, 177, 139, 50, 114, 136, 157, 202, 132, 203, 246,
            252, 242, 13, 81, 42, 100, 159, 240, 187, 252, 202, 108, 25, 105,
        ])
        .unwrap();

        let expected_pk: PublicKey = PublicKey::try_new([
            210, 59, 119, 137, 21, 153, 82, 22, 195, 82, 12, 16, 80, 156, 125, 199, 19, 173, 46,
            224, 213, 144, 165, 126, 70, 129, 171, 141, 77, 212, 108, 233,
        ])
        .unwrap();

        assert!(expected_cc == child_keys.cc);
        assert!(expected_ssk == child_keys.ssk);
        assert!(expected_sk == child_keys.sk);
        assert!(expected_pk == child_keys.pk);
    }
}
