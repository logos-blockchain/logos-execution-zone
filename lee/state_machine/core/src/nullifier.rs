use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};

use crate::{
    Commitment,
    account::{Account, AccountId},
    encryption::ViewingPublicKey,
};

const PRIVATE_ACCOUNT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/Private/\x00\x00\x00\x00";

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
    /// Derives an [`AccountId`] for a regular (non-PDA) private account from the nullifier and
    /// viewing public keys.
    #[must_use]
    pub fn for_regular_private_account(npk: &NullifierPublicKey, vpk: &ViewingPublicKey) -> Self {
        let mut bytes = [0_u8; 32 + 32 + ViewingPublicKey::LEN];
        bytes[0..32].copy_from_slice(PRIVATE_ACCOUNT_ID_PREFIX);
        bytes[32..64].copy_from_slice(&npk.0);
        bytes[64..].copy_from_slice(vpk.to_bytes());

        Self::new(
            Impl::hash_bytes(&bytes)
                .as_bytes()
                .try_into()
                .expect("Conversion should not fail"),
        )
    }
}

impl From<(&NullifierPublicKey, &ViewingPublicKey)> for AccountId {
    fn from((npk, vpk): (&NullifierPublicKey, &ViewingPublicKey)) -> Self {
        Self::for_regular_private_account(npk, vpk)
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

    /// The nullifier every initialization of `account_id` spends: its fixed empty predecessor's
    /// update nullifier, which only the holder of `nsk` can derive.
    #[must_use]
    pub fn for_account_initialization(account_id: &AccountId, nsk: &NullifierSecretKey) -> Self {
        Self::for_account_update(&Commitment::new(account_id, &Account::default()), nsk)
    }

    /// Computes the nullifier that spends a privately received message.
    #[must_use]
    pub fn for_message(nsk: &NullifierSecretKey, commitment: &Commitment, position: u64) -> Self {
        const MESSAGE_PREFIX: &[u8; 32] = b"/LEE/v0.3/Nullifier/Message/\x00\x00\x00\x00";
        let mut bytes = [0; 104];
        bytes[..32].copy_from_slice(MESSAGE_PREFIX);
        bytes[32..64].copy_from_slice(nsk);
        bytes[64..96].copy_from_slice(&commitment.to_byte_array());
        bytes[96..].copy_from_slice(&position.to_le_bytes());
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
    use crate::{account::Actor, program::MessageBody};

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
            203, 97, 5, 246, 132, 104, 64, 225, 231, 194, 207, 247, 55, 126, 113, 106, 123, 83,
            121, 172, 167, 51, 189, 170, 232, 91, 247, 94, 202, 15, 185, 98,
        ]);

        let account_id = AccountId::for_regular_private_account(&npk, &vpk);

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

    fn message_commitment() -> Commitment {
        Commitment::for_message(&MessageBody {
            from: Actor::new(AccountId::new([0; 32]), AccountId::new([1; 32])),
            to: Actor::new(AccountId::new([2; 32]), AccountId::new([3; 32])),
            message: vec![4; 2],
        })
    }

    // Every byte nonzero, so the pins fix all eight of its encoding.
    fn message_position() -> u64 {
        u64::from_le_bytes([6, 7, 8, 9, 10, 11, 12, 13])
    }

    #[test]
    fn for_message_matches_pinned_value() {
        let expected_nullifier = Nullifier([
            116, 37, 191, 177, 130, 173, 46, 17, 130, 92, 95, 98, 44, 77, 72, 166, 240, 45, 213,
            115, 155, 113, 177, 212, 80, 215, 245, 216, 42, 143, 71, 95,
        ]);
        assert_eq!(
            Nullifier::for_message(&[5; 32], &message_commitment(), message_position()),
            expected_nullifier
        );
    }
}
