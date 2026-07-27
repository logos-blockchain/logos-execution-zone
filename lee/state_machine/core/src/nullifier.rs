use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};

use crate::{AuthorizationSecretKey, Commitment, account::AccountId};

pub type Identifier = u128;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(any(feature = "host", test), derive(Hash))]
pub struct NullifierPublicKey(pub [u8; 32]);

impl AsRef<[u8]> for NullifierPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<&NullifierSecretKey> for NullifierPublicKey {
    fn from(value: &NullifierSecretKey) -> Self {
        const DOMAIN: &[u8; 31] = b"/LEE/v0.3/Keys/Nullifier/Public";

        let mut bytes = [0_u8; 31 + 32];
        bytes[0..31].copy_from_slice(DOMAIN);
        bytes[31..].copy_from_slice(value);
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

#[must_use]
pub fn derive_nullifier_secret_key(ask: &AuthorizationSecretKey) -> NullifierSecretKey {
    const DOMAIN: &[u8; 31] = b"/LEE/v0.3/Keys/Nullifier/Secret";

    let mut bytes = [0_u8; 31 + 32];
    bytes[0..31].copy_from_slice(DOMAIN);
    bytes[31..].copy_from_slice(ask);

    Impl::hash_bytes(&bytes)
        .as_bytes()
        .try_into()
        .expect("hash should be exactly 32 bytes long")
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
    fn nsk_matches_pinned_vectors() {
        // nsk = SHA256("/LEE/v0.3/Keys/Nullifier/Secret" ‖ ask); pinned via independent Python
        // SHA-256, itself validated against `for_private_pda_matches_pinned_value`.
        assert_eq!(
            derive_nullifier_secret_key(&[0; 32]),
            [
                0x1f, 0x21, 0x5a, 0x59, 0xc1, 0x0e, 0x95, 0x2e, 0x6b, 0x26, 0x33, 0x41, 0xb2, 0xf2,
                0x76, 0x0b, 0xeb, 0xc6, 0xf2, 0x90, 0xc0, 0x40, 0x27, 0xcd, 0xf4, 0x7a, 0xd2, 0x37,
                0x0b, 0xf5, 0x75, 0x1d,
            ]
        );
        assert_eq!(
            derive_nullifier_secret_key(&[1; 32]),
            [
                0xf5, 0xec, 0x71, 0x8f, 0x3e, 0x6a, 0xcb, 0x73, 0x56, 0x93, 0x8b, 0x57, 0x44, 0x96,
                0xc3, 0x41, 0x50, 0x74, 0x8a, 0xa6, 0xe2, 0x6f, 0x96, 0xc3, 0xca, 0x5d, 0xbc, 0xd1,
                0xa7, 0x7b, 0x9b, 0x69,
            ]
        );
    }

    #[test]
    fn nsk_differs_for_different_ask() {
        assert_ne!(
            derive_nullifier_secret_key(&[0; 32]),
            derive_nullifier_secret_key(&[1; 32]),
        );
    }

    #[test]
    fn npk_chains_through_nsk_from_ask() {
        // npk = KDF²(ask): the transitive binding a regular account id relies on.
        let nsk = derive_nullifier_secret_key(&[0; 32]);
        assert_eq!(
            NullifierPublicKey::from(&nsk).0,
            [
                0x20, 0xff, 0x04, 0x29, 0x15, 0xb4, 0xf3, 0x6a, 0xf1, 0x5a, 0x64, 0x06, 0x42, 0x08,
                0x35, 0x28, 0xea, 0x6f, 0xea, 0x0b, 0x93, 0x59, 0x26, 0x8a, 0xa4, 0xa7, 0x61, 0x8f,
                0x70, 0x1f, 0x4f, 0x01,
            ]
        );
    }

    #[test]
    fn from_secret_key() {
        let nsk = [
            57, 5, 64, 115, 153, 56, 184, 51, 207, 238, 99, 165, 147, 214, 213, 151, 30, 251, 30,
            196, 134, 22, 224, 211, 237, 120, 136, 225, 188, 220, 249, 28,
        ];
        let expected_npk = NullifierPublicKey([
            58, 181, 207, 24, 227, 133, 192, 231, 242, 216, 230, 219, 31, 227, 236, 94, 99, 245,
            206, 251, 237, 189, 88, 218, 215, 106, 66, 227, 136, 152, 140, 218,
        ]);
        let npk = NullifierPublicKey::from(&nsk);
        assert_eq!(npk, expected_npk);
    }
}
