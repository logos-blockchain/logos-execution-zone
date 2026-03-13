use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::{Impl, Sha256};
use serde::{Deserialize, Serialize};

use crate::{Commitment, account::AccountId};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(any(feature = "host", test), derive(Clone, Hash))]
pub struct NullifierPublicKey(pub [u8; 32]);

impl From<&NullifierPublicKey> for AccountId {
    fn from(value: &NullifierPublicKey) -> Self {
        const PRIVATE_ACCOUNT_ID_PREFIX: &[u8; 32] =
            b"/LEE/v0.3/AccountId/Private/\x00\x00\x00\x00";

        let mut bytes = [0; 64];
        bytes[0..32].copy_from_slice(PRIVATE_ACCOUNT_ID_PREFIX);
        bytes[32..].copy_from_slice(&value.0);
        AccountId::new(Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap())
    }
}

impl AsRef<[u8]> for NullifierPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<&NullifierSecretKey> for NullifierPublicKey {
    fn from(value: &NullifierSecretKey) -> Self {
        let mut bytes = Vec::new();
        const PREFIX: &[u8; 8] = b"LEE/keys";
        const SUFFIX_1: &[u8; 1] = &[7];
        const SUFFIX_2: &[u8; 23] = &[0; 23];
        bytes.extend_from_slice(PREFIX);
        bytes.extend_from_slice(value);
        bytes.extend_from_slice(SUFFIX_1);
        bytes.extend_from_slice(SUFFIX_2);
        Self(Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap())
    }
}

pub type NullifierSecretKey = [u8; 32];

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    any(feature = "host", test),
    derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)
)]
pub struct Nullifier(pub(super) [u8; 32]);

#[cfg(any(feature = "host", test))]
impl std::fmt::Debug for Nullifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex: String = self.0.iter().map(|b| format!("{b:02x}")).collect();
        write!(f, "Nullifier({hex})")
    }
}

impl Nullifier {
    pub fn for_account_update(commitment: &Commitment, nsk: &NullifierSecretKey) -> Self {
        const UPDATE_PREFIX: &[u8; 32] = b"/NSSA/v0.2/Nullifier/Update/\x00\x00\x00\x00";
        let mut bytes = UPDATE_PREFIX.to_vec();
        bytes.extend_from_slice(&commitment.to_byte_array());
        bytes.extend_from_slice(nsk);
        Self(Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap())
    }

    pub fn for_account_initialization(npk: &NullifierPublicKey) -> Self {
        const INIT_PREFIX: &[u8; 32] = b"/NSSA/v0.2/Nullifier/Initialize/";
        let mut bytes = INIT_PREFIX.to_vec();
        bytes.extend_from_slice(&npk.to_byte_array());
        Self(Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constructor_for_account_update() {
        let commitment = Commitment((0..32u8).collect::<Vec<_>>().try_into().unwrap());
        let nsk = [0x42; 32];
        let expected_nullifier = Nullifier([
            148, 243, 116, 209, 140, 231, 211, 61, 35, 62, 114, 110, 143, 224, 82, 201, 221, 34,
            53, 80, 185, 48, 174, 28, 203, 43, 94, 187, 85, 199, 115, 81,
        ]);
        let nullifier = Nullifier::for_account_update(&commitment, &nsk);
        assert_eq!(nullifier, expected_nullifier);
    }

    #[test]
    fn test_constructor_for_account_initialization() {
        let npk = NullifierPublicKey([
            112, 188, 193, 129, 150, 55, 228, 67, 88, 168, 29, 151, 5, 92, 23, 190, 17, 162, 164,
            255, 29, 105, 42, 186, 43, 11, 157, 168, 132, 225, 17, 163,
        ]);
        let expected_nullifier = Nullifier([
            1, 6, 59, 168, 16, 146, 65, 252, 255, 91, 48, 85, 116, 189, 110, 218, 110, 136, 163,
            193, 245, 103, 51, 27, 235, 170, 215, 115, 97, 144, 36, 238,
        ]);
        let nullifier = Nullifier::for_account_initialization(&npk);
        assert_eq!(nullifier, expected_nullifier);
    }

    #[test]
    fn test_from_secret_key() {
        let nsk = [
            57, 5, 64, 115, 153, 56, 184, 51, 207, 238, 99, 165, 147, 214, 213, 151, 30, 251, 30,
            196, 134, 22, 224, 211, 237, 120, 136, 225, 188, 220, 249, 28,
        ];
        let expected_npk = NullifierPublicKey([
            78, 20, 20, 5, 177, 198, 233, 100, 175, 134, 174, 200, 24, 205, 68, 215, 130, 74, 35,
            54, 154, 184, 219, 42, 168, 106, 126, 147, 133, 244, 18, 218,
        ]);
        let npk = NullifierPublicKey::from(&nsk);
        assert_eq!(npk, expected_npk);
    }

    #[test]
    fn test_account_id_from_nullifier_public_key() {
        let nsk = [
            57, 5, 64, 115, 153, 56, 184, 51, 207, 238, 99, 165, 147, 214, 213, 151, 30, 251, 30,
            196, 134, 22, 224, 211, 237, 120, 136, 225, 188, 220, 249, 28,
        ];
        let npk = NullifierPublicKey::from(&nsk);
        let expected_account_id = AccountId::new([
            139, 72, 194, 222, 215, 187, 147, 56, 55, 35, 222, 205, 156, 12, 204, 227, 166, 44, 30,
            81, 186, 14, 167, 234, 28, 236, 32, 213, 125, 251, 193, 233,
        ]);

        let account_id = AccountId::from(&npk);

        assert_eq!(account_id, expected_account_id);
    }
}
