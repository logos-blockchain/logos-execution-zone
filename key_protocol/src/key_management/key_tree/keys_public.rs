use secp256k1::Scalar;
use serde::{Deserialize, Serialize};

use crate::key_management::key_tree::traits::KeyNode;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChildKeysPublic {
    pub csk: nssa::PrivateKey,
    pub cpk: nssa::PublicKey,
    pub ccc: [u8; 32],
    /// Can be [`None`] if root
    pub cci: Option<u32>,
}

impl ChildKeysPublic {
    fn compute_hash_value(&self, cci: u32) -> [u8; 64] {
        let mut hash_input = vec![];

        match ((2u32).pow(31)).cmp(&cci) {
            // Non-harden
            std::cmp::Ordering::Greater => {
                // BIP-032 compatibility requires 1-byte header from the public_key;
                // Not stored in `self.cpk.value()`
                let sk = secp256k1::SecretKey::from_byte_array(*self.csk.value())
                    .expect("32 bytes, within curve order");
                let pk = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk);
                hash_input.extend_from_slice(&secp256k1::PublicKey::serialize(&pk));
                hash_input.extend_from_slice(&cci.to_be_bytes());

                hmac_sha512::HMAC::mac(hash_input, self.ccc)
            }
            // Harden
            _ => {
                hash_input.extend_from_slice(&[0u8]);
                hash_input.extend_from_slice(self.csk.value());
                hash_input.extend_from_slice(&cci.to_be_bytes());

                hmac_sha512::HMAC::mac(hash_input, self.ccc)
            }
        }
    }
}

impl KeyNode for ChildKeysPublic {
    fn root(seed: [u8; 64]) -> Self {
        let hash_value = hmac_sha512::HMAC::mac(seed, "LEE_master_pub");

        let csk = nssa::PrivateKey::try_new(*hash_value.first_chunk::<32>().unwrap()).unwrap();
        let ccc = *hash_value.last_chunk::<32>().unwrap();
        let cpk = nssa::PublicKey::new_from_private_key(&csk);

        Self {
            csk,
            cpk,
            ccc,
            cci: None,
        }
    }

    fn nth_child(&self, cci: u32) -> Self {
        let hash_value = self.compute_hash_value(cci);

        let csk = secp256k1::SecretKey::from_byte_array(
            *hash_value
                .first_chunk::<32>()
                .expect("hash_value is 64 bytes, must be safe to get first 32"),
        )
        .unwrap();

        let csk = nssa::PrivateKey::try_new(
            csk.add_tweak(&Scalar::from_be_bytes(*self.csk.value()).unwrap())
                .expect("Expect a valid Scalar")
                .secret_bytes(),
        )
        .unwrap();

        if secp256k1::constants::CURVE_ORDER < *csk.value() {
            panic!("Secret key cannot exceed curve order");
        }

        let ccc = *hash_value
            .last_chunk::<32>()
            .expect("hash_value is 64 bytes, must be safe to get last 32");

        let cpk = nssa::PublicKey::new_from_private_key(&csk);

        Self {
            csk,
            cpk,
            ccc,
            cci: Some(cci),
        }
    }

    fn chain_code(&self) -> &[u8; 32] {
        &self.ccc
    }

    fn child_index(&self) -> Option<u32> {
        self.cci
    }

    fn account_id(&self) -> nssa::AccountId {
        nssa::AccountId::from(&self.cpk)
    }
}

impl<'a> From<&'a ChildKeysPublic> for &'a nssa::PrivateKey {
    fn from(value: &'a ChildKeysPublic) -> Self {
        &value.csk
    }
}

#[cfg(test)]
mod tests {
    use nssa::{PrivateKey, PublicKey};

    use super::*;

    #[test]
    fn test_master_keys_generation() {
        let seed = [
            88, 189, 37, 237, 199, 125, 151, 226, 69, 153, 165, 113, 191, 69, 188, 221, 9, 34, 173,
            134, 61, 109, 34, 103, 121, 39, 237, 14, 107, 194, 24, 194, 191, 14, 237, 185, 12, 87,
            22, 227, 38, 71, 17, 144, 251, 118, 217, 115, 33, 222, 201, 61, 203, 246, 121, 214, 6,
            187, 148, 92, 44, 253, 210, 37,
        ];
        let keys = ChildKeysPublic::root(seed);

        let expected_ccc = [
            238, 94, 84, 154, 56, 224, 80, 218, 133, 249, 179, 222, 9, 24, 17, 252, 120, 127, 222,
            13, 146, 126, 232, 239, 113, 9, 194, 219, 190, 48, 187, 155,
        ];

        let expected_csk: PrivateKey = PrivateKey::try_new([
            40, 35, 239, 19, 53, 178, 250, 55, 115, 12, 34, 3, 153, 153, 72, 170, 190, 36, 172, 36,
            202, 148, 181, 228, 35, 222, 58, 84, 156, 24, 146, 86,
        ])
        .unwrap();

        let expected_cpk: PublicKey = PublicKey::try_new([
            219, 141, 130, 105, 11, 203, 187, 124, 112, 75, 223, 22, 11, 164, 153, 127, 59, 247,
            244, 166, 75, 66, 242, 224, 35, 156, 161, 75, 41, 51, 76, 245,
        ])
        .unwrap();

        assert!(expected_ccc == keys.ccc);
        assert!(expected_csk == keys.csk);
        assert!(expected_cpk == keys.cpk);
    }

    #[test]
    fn test_harden_child_keys_generation() {
        let seed = [
            88, 189, 37, 237, 199, 125, 151, 226, 69, 153, 165, 113, 191, 69, 188, 221, 9, 34, 173,
            134, 61, 109, 34, 103, 121, 39, 237, 14, 107, 194, 24, 194, 191, 14, 237, 185, 12, 87,
            22, 227, 38, 71, 17, 144, 251, 118, 217, 115, 33, 222, 201, 61, 203, 246, 121, 214, 6,
            187, 148, 92, 44, 253, 210, 37,
        ];
        let root_keys = ChildKeysPublic::root(seed);
        let cci = (2u32).pow(31) + 13;
        let child_keys = ChildKeysPublic::nth_child(&root_keys, cci);

        let expected_ccc = [
            149, 226, 13, 4, 194, 12, 69, 29, 9, 234, 209, 119, 98, 4, 128, 91, 37, 103, 192, 31,
            130, 126, 123, 20, 90, 34, 173, 209, 101, 248, 155, 36,
        ];

        let expected_csk: PrivateKey = PrivateKey::try_new([
            9, 65, 33, 228, 25, 82, 219, 117, 91, 217, 11, 223, 144, 85, 246, 26, 123, 216, 107,
            213, 33, 52, 188, 22, 198, 246, 71, 46, 245, 174, 16, 47,
        ])
        .unwrap();

        let expected_cpk: PublicKey = PublicKey::try_new([
            142, 143, 238, 159, 105, 165, 224, 252, 108, 62, 53, 209, 176, 219, 249, 38, 90, 241,
            201, 81, 194, 146, 236, 5, 83, 152, 238, 243, 138, 16, 229, 15,
        ])
        .unwrap();

        assert!(expected_ccc == child_keys.ccc);
        assert!(expected_csk == child_keys.csk);
        assert!(expected_cpk == child_keys.cpk);
    }

    #[test]
    fn test_nonharden_child_keys_generation() {
        let seed = [
            88, 189, 37, 237, 199, 125, 151, 226, 69, 153, 165, 113, 191, 69, 188, 221, 9, 34, 173,
            134, 61, 109, 34, 103, 121, 39, 237, 14, 107, 194, 24, 194, 191, 14, 237, 185, 12, 87,
            22, 227, 38, 71, 17, 144, 251, 118, 217, 115, 33, 222, 201, 61, 203, 246, 121, 214, 6,
            187, 148, 92, 44, 253, 210, 37,
        ];
        let root_keys = ChildKeysPublic::root(seed);
        let cci = 13;
        let child_keys = ChildKeysPublic::nth_child(&root_keys, cci);

        let expected_ccc = [
            79, 228, 242, 119, 211, 203, 198, 175, 95, 36, 4, 234, 139, 45, 137, 138, 54, 211, 187,
            16, 28, 79, 80, 232, 216, 101, 145, 19, 101, 220, 217, 141,
        ];

        let expected_csk: PrivateKey = PrivateKey::try_new([
            185, 147, 32, 242, 145, 91, 123, 77, 42, 33, 134, 84, 12, 165, 117, 70, 158, 201, 95,
            153, 14, 12, 92, 235, 128, 156, 194, 169, 68, 35, 165, 127,
        ])
        .unwrap();

        let expected_cpk: PublicKey = PublicKey::try_new([
            119, 16, 145, 121, 97, 244, 186, 35, 136, 34, 140, 171, 206, 139, 11, 208, 207, 121,
            158, 45, 28, 22, 140, 98, 161, 179, 212, 173, 238, 220, 2, 34,
        ])
        .unwrap();

        assert!(expected_ccc == child_keys.ccc);
        assert!(expected_csk == child_keys.csk);
        assert!(expected_cpk == child_keys.cpk);
    }

    #[test]
    fn test_edge_case_child_keys_generation_2_power_31() {
        let seed = [
            88, 189, 37, 237, 199, 125, 151, 226, 69, 153, 165, 113, 191, 69, 188, 221, 9, 34, 173,
            134, 61, 109, 34, 103, 121, 39, 237, 14, 107, 194, 24, 194, 191, 14, 237, 185, 12, 87,
            22, 227, 38, 71, 17, 144, 251, 118, 217, 115, 33, 222, 201, 61, 203, 246, 121, 214, 6,
            187, 148, 92, 44, 253, 210, 37,
        ];
        let root_keys = ChildKeysPublic::root(seed);
        let cci = (2u32).pow(31); //equivant to 0, thus non-harden.
        let child_keys = ChildKeysPublic::nth_child(&root_keys, cci);

        let expected_ccc = [
            221, 208, 47, 189, 174, 152, 33, 25, 151, 114, 233, 191, 57, 15, 40, 140, 46, 87, 126,
            58, 215, 40, 246, 111, 166, 113, 183, 145, 173, 11, 27, 182,
        ];

        let expected_csk: PrivateKey = PrivateKey::try_new([
            223, 29, 87, 189, 126, 24, 117, 225, 190, 57, 0, 143, 207, 168, 231, 139, 170, 192, 81,
            254, 126, 10, 115, 42, 141, 157, 70, 171, 199, 231, 198, 132,
        ])
        .unwrap();

        let expected_cpk: PublicKey = PublicKey::try_new([
            96, 123, 245, 51, 214, 216, 215, 205, 70, 145, 105, 221, 166, 169, 122, 27, 94, 112,
            228, 110, 249, 177, 85, 173, 180, 248, 185, 199, 112, 246, 83, 33,
        ])
        .unwrap();

        assert!(expected_ccc == child_keys.ccc);
        assert!(expected_csk == child_keys.csk);
        assert!(expected_cpk == child_keys.cpk);
    }
}
