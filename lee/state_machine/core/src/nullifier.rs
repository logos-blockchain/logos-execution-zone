use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};

use crate::{Commitment, account::AccountId, encryption::ViewingPublicKey};

const PRIVATE_ACCOUNT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/Private/\x00\x00\x00\x00";

pub type Identifier = u128;

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(any(feature = "host", test), derive(Hash))]
pub struct NullifierPublicKey(pub [u8; 32]);

impl AccountId {
    /// Derives an [`AccountId`] for a regular (non-PDA) private account from the nullifier public
    /// key and identifier.
    #[must_use]
    pub fn for_regular_private_account(
        npk: &NullifierPublicKey,
        vpk: &ViewingPublicKey,
        identifier: Identifier,
    ) -> Self {
        let mut bytes = [0_u8; 32 + 32 + ViewingPublicKey::LEN + 16];
        bytes[0..32].copy_from_slice(PRIVATE_ACCOUNT_ID_PREFIX);
        bytes[32..64].copy_from_slice(&npk.0);
        bytes[64..64 + ViewingPublicKey::LEN].copy_from_slice(vpk.to_bytes());
        bytes[64 + ViewingPublicKey::LEN..].copy_from_slice(&identifier.to_le_bytes());

        Self::new(
            Impl::hash_bytes(&bytes)
                .as_bytes()
                .try_into()
                .expect("Conversion should not fail"),
        )
    }
}

impl From<(&NullifierPublicKey, &ViewingPublicKey, Identifier)> for AccountId {
    fn from((npk, vpk, identifier): (&NullifierPublicKey, &ViewingPublicKey, Identifier)) -> Self {
        Self::for_regular_private_account(npk, vpk, identifier)
    }
}

impl AsRef<[u8]> for NullifierPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(any(feature = "host", test), derive(Hash))]
pub struct AuthorizationSecretKey(pub [u8; 32]);

impl From<&AuthorizationSecretKey> for NullifierSecretKey {
    fn from(value: &AuthorizationSecretKey) -> Self {
        const DOMAIN: &[u8; 29] = b"/LEE-Keys/v1/Nullifier/Secret";
        let mut bytes = [0_u8; 29 + 32];
        bytes[..29].copy_from_slice(DOMAIN);
        bytes[29..].copy_from_slice(&value.0);
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("hash should be exactly 32 bytes long")
    }
}

impl From<&NullifierSecretKey> for NullifierPublicKey {
    fn from(value: &NullifierSecretKey) -> Self {
        const DOMAIN: &[u8; 29] = b"/LEE-Keys/v1/Nullifier/Public";
        let mut bytes = [0_u8; 29 + 32];
        bytes[..29].copy_from_slice(DOMAIN);
        bytes[29..].copy_from_slice(value);
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
    derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)
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

    #[must_use]
    pub fn for_dummy(nullifier_seed: &[u8; 32]) -> Self {
        const DUMMY_PREFIX: &[u8; 32] = b"/LEE/v0.3/Nullifier/Dummy/\x00\x00\x00\x00\x00\x00";
        let mut bytes = DUMMY_PREFIX.to_vec();
        bytes.extend_from_slice(nullifier_seed);
        Self(Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap())
    }

    #[must_use]
    pub const fn to_byte_array(&self) -> [u8; 32] {
        self.0
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
    fn from_authorization_key() {
        let ask = AuthorizationSecretKey([0; 32]);
        let expected_nsk: NullifierSecretKey = [
            135, 144, 25, 255, 27, 190, 82, 191, 49, 83, 55, 248, 251, 98, 149, 55, 143, 129, 2,
            201, 237, 77, 248, 237, 15, 11, 188, 41, 219, 213, 10, 74,
        ];
        let nsk = NullifierSecretKey::from(&ask);
        assert_eq!(nsk, expected_nsk);
    }

    #[test]
    fn from_secret_key() {
        let nsk = [
            57, 5, 64, 115, 153, 56, 184, 51, 207, 238, 99, 165, 147, 214, 213, 151, 30, 251, 30,
            196, 134, 22, 224, 211, 237, 120, 136, 225, 188, 220, 249, 28,
        ];
        let expected_npk = NullifierPublicKey([
            44, 121, 113, 131, 34, 101, 53, 97, 87, 111, 83, 78, 157, 34, 59, 248, 105, 103, 194,
            137, 127, 221, 25, 17, 105, 84, 114, 129, 183, 83, 168, 193,
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
        let expected_account_id = AccountId::new([
            6, 35, 121, 102, 237, 184, 156, 247, 28, 185, 212, 214, 51, 229, 66, 170, 10, 75, 126,
            12, 93, 139, 88, 61, 65, 246, 230, 184, 223, 232, 252, 124,
        ]);

        let account_id = AccountId::for_regular_private_account(&npk, &vpk, 0);

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
        let expected_account_id = AccountId::new([
            56, 217, 214, 244, 51, 212, 184, 73, 217, 85, 4, 126, 54, 35, 135, 225, 75, 253, 183,
            19, 96, 182, 189, 138, 62, 101, 131, 30, 2, 236, 157, 235,
        ]);

        let account_id = AccountId::for_regular_private_account(&npk, &vpk, 1);

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
        let expected_account_id = AccountId::new([
            14, 231, 97, 140, 18, 163, 250, 222, 102, 223, 118, 160, 65, 228, 201, 232, 182, 198,
            230, 213, 216, 143, 78, 95, 163, 95, 32, 1, 20, 240, 97, 95,
        ]);

        let account_id = AccountId::for_regular_private_account(&npk, &vpk, identifier);

        assert_eq!(account_id, expected_account_id);
    }

    #[test]
    fn for_dummy_matches_pinned_value() {
        let nullifier_seed = [0; 32];
        let expected_nullifier = Nullifier([
            244, 220, 48, 137, 204, 138, 180, 41, 108, 86, 40, 46, 187, 7, 232, 57, 57, 167, 143,
            157, 125, 171, 137, 46, 64, 206, 191, 211, 231, 0, 11, 86,
        ]);
        assert_eq!(Nullifier::for_dummy(&nullifier_seed), expected_nullifier);
    }
}
