use base58::{FromBase58 as _, ToBase58 as _};
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::{Commitment, account::AccountId, encryption::ViewingPublicKey};

const PRIVATE_ACCOUNT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/Private/\x00\x00\x00\x00";

/// 256-bit opaque private-account identifier.
#[derive(
    Copy,
    Clone,
    SerializeDisplay,
    DeserializeFromStr,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Debug,
    derive_more::Display,
    derive_more::AsRef,
)]
#[debug("{}", value.to_base58())]
#[display("{}", value.to_base58())]
pub struct Identifier {
    #[as_ref([u8])]
    value: [u8; 32],
}

impl Identifier {
    pub const ZERO: Self = Self { value: [0; 32] };

    #[must_use]
    pub const fn new(value: [u8; 32]) -> Self {
        Self { value }
    }

    #[must_use]
    pub const fn value(&self) -> &[u8; 32] {
        &self.value
    }

    #[must_use]
    pub const fn into_value(self) -> [u8; 32] {
        self.value
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdentifierError {
    #[error("invalid base58: {0:?}")]
    InvalidBase58(base58::FromBase58Error),
    #[error("invalid length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
}

impl std::str::FromStr for Identifier {
    type Err = IdentifierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.from_base58().map_err(IdentifierError::InvalidBase58)?;
        if bytes.len() != 32 {
            return Err(IdentifierError::InvalidLength(bytes.len()));
        }
        let mut value = [0_u8; 32];
        value.copy_from_slice(&bytes);
        Ok(Self { value })
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
        let mut bytes = [0_u8; 32 + 32 + ViewingPublicKey::LEN + 32];
        bytes[0..32].copy_from_slice(PRIVATE_ACCOUNT_ID_PREFIX);
        bytes[32..64].copy_from_slice(&npk.0);
        bytes[64..64 + ViewingPublicKey::LEN].copy_from_slice(vpk.to_bytes());
        bytes[64 + ViewingPublicKey::LEN..].copy_from_slice(identifier.value());

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
            211, 228, 241, 40, 66, 75, 99, 113, 149, 61, 234, 62, 12, 139, 200, 82, 83, 147, 50,
            118, 187, 238, 65, 251, 54, 229, 89, 151, 17, 104, 62, 240,
        ]);

        let account_id = AccountId::for_regular_private_account(&npk, &vpk, Identifier::ZERO);

        assert_eq!(account_id, expected_account_id);
    }

    #[test]
    fn account_id_from_nullifier_public_key_nonzero_identifier() {
        let nsk = [
            57, 5, 64, 115, 153, 56, 184, 51, 207, 238, 99, 165, 147, 214, 213, 151, 30, 251, 30,
            196, 134, 22, 224, 211, 237, 120, 136, 225, 188, 220, 249, 28,
        ];
        let npk = NullifierPublicKey::from(&nsk);
        let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
        let expected_account_id = AccountId::new([
            219, 234, 210, 62, 137, 169, 241, 66, 19, 208, 42, 125, 253, 19, 55, 204, 144, 57, 22,
            196, 199, 246, 104, 134, 232, 84, 164, 19, 42, 152, 118, 210,
        ]);

        let account_id =
            AccountId::for_regular_private_account(&npk, &vpk, Identifier::new([1; 32]));

        assert_eq!(account_id, expected_account_id);
    }

    #[test]
    fn account_id_from_nullifier_public_key_byte_asymmetric_identifier() {
        // Every byte position distinct, to catch a byte-order bug anywhere in the width.
        let identifier = Identifier::new([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ]);
        let nsk = [
            57, 5, 64, 115, 153, 56, 184, 51, 207, 238, 99, 165, 147, 214, 213, 151, 30, 251, 30,
            196, 134, 22, 224, 211, 237, 120, 136, 225, 188, 220, 249, 28,
        ];
        let npk = NullifierPublicKey::from(&nsk);
        let vpk = ViewingPublicKey::from_seed(&[1_u8; 32], &[2_u8; 32]);
        let expected_account_id = AccountId::new([
            223, 65, 35, 211, 3, 244, 181, 174, 35, 212, 132, 168, 231, 60, 74, 241, 60, 71, 246,
            117, 97, 139, 50, 168, 136, 239, 94, 200, 165, 223, 250, 92,
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

    #[test]
    fn identifier_display_from_str_round_trip() {
        for identifier in [
            Identifier::ZERO,
            Identifier::new([0xff; 32]),
            Identifier::new(core::array::from_fn(|i| u8::try_from(i).unwrap())),
        ] {
            let round_tripped: Identifier = identifier.to_string().parse().unwrap();
            assert_eq!(round_tripped, identifier);
            assert_eq!(format!("{identifier:?}"), identifier.to_string());
        }
    }

    #[test]
    fn identifier_display_matches_pinned_base58() {
        assert_eq!(Identifier::ZERO.to_string(), "1".repeat(32));
        assert_eq!(
            Identifier::new([1; 32]).to_string(),
            "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
        );
    }

    #[test]
    fn identifier_serde_json_round_trip() {
        let identifier = Identifier::new(core::array::from_fn(|i| u8::try_from(i).unwrap()));
        let json = serde_json::to_string(&identifier).unwrap();
        let round_tripped: Identifier = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped, identifier);
    }

    #[test]
    fn identifier_from_str_rejects_invalid_base58() {
        let err = "0OIl".parse::<Identifier>().unwrap_err();
        assert!(matches!(err, IdentifierError::InvalidBase58(_)));
    }

    #[test]
    fn identifier_from_str_rejects_wrong_length() {
        let too_short = [1_u8; 16].to_base58();
        let err = too_short.parse::<Identifier>().unwrap_err();
        assert!(matches!(err, IdentifierError::InvalidLength(16)));
    }
}
