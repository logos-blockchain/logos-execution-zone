use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};

use crate::{AuthorizationPublicKey, Commitment, account::AccountId, encryption::ViewingPublicKey};

const PRIVATE_ACCOUNT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/Private/\x00\x00\x00\x00";

pub type Identifier = u128;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(Hash))]
pub struct NullifierPublicKey(pub [u8; 32]);

impl AccountId {
    /// Derives an [`AccountId`] for a regular (non-PDA) private account from the nullifier public
    /// key and identifier.
    #[must_use]
    pub fn for_regular_private_account(
        npk: &NullifierPublicKey,
        apk: &AuthorizationPublicKey,
        vpk: &ViewingPublicKey,
        identifier: Identifier,
    ) -> Self {
        let mut bytes = [0_u8; 32 + 32 + 32 + ViewingPublicKey::LEN + 16];
        bytes[0..32].copy_from_slice(PRIVATE_ACCOUNT_ID_PREFIX);
        bytes[32..64].copy_from_slice(&npk.0);
        bytes[64..96].copy_from_slice(&apk.0);
        bytes[96..96 + ViewingPublicKey::LEN].copy_from_slice(vpk.to_bytes());
        bytes[96 + ViewingPublicKey::LEN..].copy_from_slice(&identifier.to_le_bytes());

        Self::from_preimage(&bytes)
    }
}

impl AsRef<[u8]> for NullifierPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<&NullifierSecretKey> for NullifierPublicKey {
    fn from(value: &NullifierSecretKey) -> Self {
        const PREFIX: &[u8; 8] = b"LEE/keys";
        const SUFFIX_1: &[u8; 1] = &[7];
        const SUFFIX_2: &[u8; 23] = &[0; 23];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(PREFIX);
        bytes.extend_from_slice(value);
        bytes.extend_from_slice(SUFFIX_1);
        bytes.extend_from_slice(SUFFIX_2);
        Self(
            Impl::hash_bytes(&bytes)
                .as_bytes()
                .try_into()
                .expect("hash should be exactly 32 bytes long"),
        )
    }
}

pub type NullifierSecretKey = [u8; 32];

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    any(feature = "host", test),
    derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)
)]
pub struct Nullifier(pub(super) [u8; 32]);

#[cfg(any(feature = "host", test))]
impl std::fmt::Debug for Nullifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;

        let hex: String = self.0.iter().fold(String::new(), |mut acc, b| {
            write!(acc, "{b:02x}").expect("writing to string should not fail");
            acc
        });
        write!(f, "Nullifier({hex})")
    }
}

impl Nullifier {
    /// Computes a nullifier for an account update.
    #[must_use]
    pub fn for_account_update(commitment: &Commitment, nsk: &NullifierSecretKey) -> Self {
        const UPDATE_PREFIX: &[u8; 32] = b"/LEE/v0.3/Nullifier/Update/\x00\x00\x00\x00\x00";
        let mut bytes = UPDATE_PREFIX.to_vec();
        bytes.extend_from_slice(&commitment.to_byte_array());
        bytes.extend_from_slice(nsk);
        Self(Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap())
    }

    /// Computes a nullifier for an account initialization.
    // TODO: Accept account_id by value as it's Copy
    #[must_use]
    pub fn for_account_initialization(account_id: &AccountId) -> Self {
        const INIT_PREFIX: &[u8; 32] = b"/LEE/v0.3/Nullifier/Initialize/\x00";
        let mut bytes = INIT_PREFIX.to_vec();
        bytes.extend_from_slice(account_id.value());
        Self(Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_for_account_update() {
        let commitment = Commitment((0..32_u8).collect::<Vec<_>>().try_into().unwrap());
        let nsk = [0x42; 32];
        let expected_nullifier = Nullifier([
            70, 162, 122, 15, 33, 237, 244, 216, 89, 223, 90, 50, 94, 184, 210, 144, 174, 64, 189,
            254, 62, 255, 5, 1, 139, 227, 194, 185, 16, 30, 55, 48,
        ]);
        let nullifier = Nullifier::for_account_update(&commitment, &nsk);
        assert_eq!(nullifier, expected_nullifier);
    }

    #[test]
    fn constructor_for_account_initialization() {
        let account_id = AccountId::new([
            112, 188, 193, 129, 150, 55, 228, 67, 88, 168, 29, 151, 5, 92, 23, 190, 17, 162, 164,
            255, 29, 105, 42, 186, 43, 11, 157, 168, 132, 225, 17, 163,
        ]);
        let expected_nullifier = Nullifier([
            149, 59, 95, 181, 2, 194, 20, 143, 72, 233, 104, 243, 59, 70, 67, 243, 110, 77, 109,
            132, 139, 111, 51, 125, 128, 92, 107, 46, 252, 4, 20, 149,
        ]);
        let nullifier = Nullifier::for_account_initialization(&account_id);
        assert_eq!(nullifier, expected_nullifier);
    }

    #[test]
    fn from_secret_key() {
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
    fn account_id_from_nullifier_public_key() {
        let nsk = [
            57, 5, 64, 115, 153, 56, 184, 51, 207, 238, 99, 165, 147, 214, 213, 151, 30, 251, 30,
            196, 134, 22, 224, 211, 237, 120, 136, 225, 188, 220, 249, 28,
        ];
        let npk = NullifierPublicKey::from(&nsk);
        let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
        let apk = AuthorizationPublicKey::from(&[0_u8; 32]);
        let expected_account_id = AccountId::new([
            42, 9, 42, 240, 164, 236, 108, 212, 207, 70, 3, 36, 45, 100, 174, 224, 196, 120, 230,
            121, 141, 3, 107, 107, 218, 174, 90, 205, 224, 196, 121, 226,
        ]);

        let account_id = AccountId::for_regular_private_account(&npk, &apk, &vpk, 0);

        assert_eq!(account_id, expected_account_id);
    }

    #[test]
    fn account_id_from_nullifier_public_key_identifier_1() {
        let nsk = [
            57, 5, 64, 115, 153, 56, 184, 51, 207, 238, 99, 165, 147, 214, 213, 151, 30, 251, 30,
            196, 134, 22, 224, 211, 237, 120, 136, 225, 188, 220, 249, 28,
        ];
        let npk = NullifierPublicKey::from(&nsk);
        let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
        let apk = AuthorizationPublicKey::from(&[0_u8; 32]);
        let expected_account_id = AccountId::new([
            118, 221, 158, 206, 184, 31, 48, 37, 62, 91, 133, 5, 11, 118, 62, 67, 219, 234, 142,
            199, 97, 104, 46, 214, 251, 107, 188, 57, 48, 104, 137, 189,
        ]);

        let account_id = AccountId::for_regular_private_account(&npk, &apk, &vpk, 1);

        assert_eq!(account_id, expected_account_id);
    }

    #[test]
    fn account_id_from_nullifier_public_key_byte_asymmetric_identifier() {
        let identifier: u128 = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210;
        let nsk = [
            57, 5, 64, 115, 153, 56, 184, 51, 207, 238, 99, 165, 147, 214, 213, 151, 30, 251, 30,
            196, 134, 22, 224, 211, 237, 120, 136, 225, 188, 220, 249, 28,
        ];
        let npk = NullifierPublicKey::from(&nsk);
        let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
        let apk = AuthorizationPublicKey::from(&[0_u8; 32]);
        let expected_account_id = AccountId::new([
            250, 189, 137, 39, 9, 107, 233, 79, 185, 205, 249, 114, 177, 45, 180, 43, 17, 147, 120,
            175, 118, 210, 93, 32, 51, 16, 10, 34, 243, 89, 192, 101,
        ]);

        let account_id = AccountId::for_regular_private_account(&npk, &apk, &vpk, identifier);

        assert_eq!(account_id, expected_account_id);
    }
}
