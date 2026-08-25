use std::{collections::BTreeMap, fmt::Display, str::FromStr};

use base58::{FromBase58 as _, ToBase58 as _};
use borsh::{BorshDeserialize, BorshSerialize};
pub use data::Data;
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::NullifierSecretKey;

pub mod data;

#[derive(Copy, Debug, Default, Clone, Eq, PartialEq)]
pub struct Nonce(pub u128);

impl Nonce {
    pub const fn public_account_nonce_increment(&mut self) {
        self.0 = self
            .0
            .checked_add(1)
            .expect("Overflow when incrementing nonce");
    }

    #[must_use]
    pub fn private_account_nonce_init(account_id: &AccountId) -> Self {
        let mut bytes: [u8; 64] = [0_u8; 64];
        bytes[..32].copy_from_slice(account_id.value());
        let result: [u8; 32] = Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap();
        let result = result.first_chunk::<16>().unwrap();

        Self(u128::from_le_bytes(*result))
    }

    #[must_use]
    pub fn private_account_nonce_increment(self, nsk: &NullifierSecretKey) -> Self {
        let mut bytes: [u8; 64] = [0_u8; 64];
        bytes[..32].copy_from_slice(nsk);
        bytes[32..48].copy_from_slice(&self.0.to_le_bytes());
        let result: [u8; 32] = Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap();
        let result = result.first_chunk::<16>().unwrap();

        Self(u128::from_le_bytes(*result))
    }
}

impl From<u128> for Nonce {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<Nonce> for u128 {
    fn from(value: Nonce) -> Self {
        value.0
    }
}

impl Serialize for Nonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Serialize::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(<u128 as Deserialize>::deserialize(deserializer)?.into())
    }
}

impl BorshSerialize for Nonce {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.0, writer)
    }
}

impl BorshDeserialize for Nonce {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(<u128 as BorshDeserialize>::deserialize_reader(reader)?.into())
    }
}

pub type Balance = u128;

/// A single program's namespace inside an account. Every program may read every slot,
/// may write only its own, and may credit balance to any.
#[derive(
    Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Slot {
    pub balance: Balance,
    pub data: Data,
}

impl Slot {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Account to be used both in public and private contexts.
///
/// There is no owner: an account is a map from program to that program's private namespace.
/// `BTreeMap` rather than `HashMap` because the account is hashed into commitments, so its
/// encoding must be canonical. Empty slots are never stored (see `validate_execution`), so
/// equal accounts always encode identically.
#[derive(
    Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Account {
    pub nonce: Nonce,
    pub slots: BTreeMap<AccountId, Slot>,
}

impl Account {
    #[must_use]
    pub fn slot(&self, program: impl Into<AccountId>) -> Option<&Slot> {
        self.slots.get(&program.into())
    }

    /// The slot a program writes through. Vacant slots materialize as empty.
    pub fn slot_mut(&mut self, program: impl Into<AccountId>) -> &mut Slot {
        self.slots.entry(program.into()).or_default()
    }

    #[must_use]
    pub fn balance(&self, program: impl Into<AccountId>) -> Balance {
        self.slot(program).map_or(0, |slot| slot.balance)
    }

    #[must_use]
    pub fn data(&self, program: impl Into<AccountId>) -> &Data {
        const EMPTY: &Data = &Data::empty();
        self.slot(program).map_or(EMPTY, |slot| &slot.data)
    }

    /// Drops slots that have become empty, keeping the encoding canonical.
    pub fn prune(&mut self) {
        self.slots.retain(|_, slot| !slot.is_empty());
    }

    /// An account whose only occupied slot belongs to `program_id`.
    #[must_use]
    pub fn single(
        program: impl Into<AccountId>,
        balance: Balance,
        data: Data,
        nonce: Nonce,
    ) -> Self {
        let slot = Slot { balance, data };
        let mut account = Self {
            nonce,
            slots: BTreeMap::new(),
        };
        if !slot.is_empty() {
            account.slots.insert(program.into(), slot);
        }
        account
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AccountWithMetadata {
    pub account: Account,
    pub is_authorized: bool,
    pub account_id: AccountId,
}

#[cfg(feature = "host")]
impl AccountWithMetadata {
    pub fn new(account: Account, is_authorized: bool, account_id: impl Into<AccountId>) -> Self {
        Self {
            account,
            is_authorized,
            account_id: account_id.into(),
        }
    }
}

#[derive(
    Default,
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
)]
pub struct AccountId {
    value: [u8; 32],
}

impl std::fmt::Debug for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value.to_base58())
    }
}

impl AccountId {
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

impl AsRef<[u8]> for AccountId {
    fn as_ref(&self) -> &[u8] {
        &self.value
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccountIdError {
    #[error("invalid base58: {0:?}")]
    InvalidBase58(base58::FromBase58Error),
    #[error("invalid length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
}

impl FromStr for AccountId {
    type Err = AccountIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.from_base58().map_err(AccountIdError::InvalidBase58)?;
        if bytes.len() != 32 {
            return Err(AccountIdError::InvalidLength(bytes.len()));
        }
        let mut value = [0_u8; 32];
        value.copy_from_slice(&bytes);
        Ok(Self { value })
    }
}

impl Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::DEFAULT_PROGRAM_ID;

    #[test]
    fn zero_balance_account_data_creation() {
        let new_acc = Account::default();

        assert_eq!(new_acc.balance(DEFAULT_PROGRAM_ID), 0);
    }

    #[test]
    fn zero_nonce_account_data_creation() {
        let new_acc = Account::default();

        assert_eq!(new_acc.nonce.0, 0);
    }

    #[test]
    fn empty_data_account_data_creation() {
        let new_acc = Account::default();

        assert!(new_acc.data(DEFAULT_PROGRAM_ID).is_empty());
    }

    #[test]
    fn no_slots_on_account_data_creation() {
        let new_acc = Account::default();

        assert!(new_acc.slots.is_empty());
    }

    #[cfg(feature = "host")]
    #[test]
    fn account_with_metadata_constructor() {
        let account = Account::single(
            [1, 2, 3, 4, 5, 6, 7, 8],
            1337,
            b"testing_account_with_metadata_constructor"
                .to_vec()
                .try_into()
                .unwrap(),
            Nonce(0xdead_beef),
        );
        let fingerprint = AccountId::new([8; 32]);
        let new_acc_with_metadata = AccountWithMetadata::new(account.clone(), true, fingerprint);
        assert_eq!(new_acc_with_metadata.account, account);
        assert!(new_acc_with_metadata.is_authorized);
        assert_eq!(new_acc_with_metadata.account_id, fingerprint);
    }

    #[cfg(feature = "host")]
    #[test]
    fn parse_valid_account_id() {
        let base58_str = "11111111111111111111111111111111";
        let account_id: AccountId = base58_str.parse().unwrap();
        assert_eq!(account_id.value, [0_u8; 32]);
    }

    #[cfg(feature = "host")]
    #[test]
    fn parse_invalid_base58() {
        let base58_str = "00".repeat(32); // invalid base58 chars
        let result = base58_str.parse::<AccountId>().unwrap_err();
        assert!(matches!(result, AccountIdError::InvalidBase58(_)));
    }

    #[cfg(feature = "host")]
    #[test]
    fn parse_wrong_length_short() {
        let base58_str = "11".repeat(31); // 62 chars = 31 bytes
        let result = base58_str.parse::<AccountId>().unwrap_err();
        assert!(matches!(result, AccountIdError::InvalidLength(_)));
    }

    #[cfg(feature = "host")]
    #[test]
    fn parse_wrong_length_long() {
        let base58_str = "11".repeat(33); // 66 chars = 33 bytes
        let result = base58_str.parse::<AccountId>().unwrap_err();
        assert!(matches!(result, AccountIdError::InvalidLength(_)));
    }

    #[test]
    fn default_account_id() {
        let default_account_id = AccountId::default();
        let expected_account_id = AccountId::new([0; 32]);
        assert!(default_account_id == expected_account_id);
    }

    #[test]
    fn initialize_private_nonce() {
        let account_id = AccountId::new([42; 32]);
        let nonce = Nonce::private_account_nonce_init(&account_id);
        let expected_nonce = Nonce(37_937_661_125_547_691_021_612_781_941_709_513_486);
        assert_eq!(nonce, expected_nonce);
    }

    #[test]
    fn increment_private_nonce() {
        let nsk: NullifierSecretKey = [42_u8; 32];
        let nonce = Nonce(37_937_661_125_547_691_021_612_781_941_709_513_486)
            .private_account_nonce_increment(&nsk);
        let expected_nonce = Nonce(327_300_903_218_789_900_388_409_116_014_290_259_894);
        assert_eq!(nonce, expected_nonce);
    }

    #[test]
    fn increment_public_nonce() {
        let value = 42_u128;
        let mut nonce = Nonce(value);
        nonce.public_account_nonce_increment();
        let expected_nonce = Nonce(value + 1);
        assert_eq!(nonce, expected_nonce);
    }

    #[test]
    fn serde_roundtrip_for_nonce() {
        let nonce: Nonce = 7_u128.into();

        let serde_serialized_nonce = serde_json::to_vec(&nonce).unwrap();

        let nonce_restored = serde_json::from_slice(&serde_serialized_nonce).unwrap();

        assert_eq!(nonce, nonce_restored);
    }

    #[test]
    fn account_round_trips_through_json() {
        // The wallet persists accounts as JSON, and `ProgramId` is `[u32; 8]`, which serde_json
        // refuses as a map key. Serializing `slots` as pairs is what keeps that working.
        let account = Account::single(
            [1, 2, 3, 4, 5, 6, 7, 8],
            42,
            b"hello".to_vec().try_into().unwrap(),
            Nonce(7),
        );
        let json = serde_json::to_string(&account).expect("account must serialize as JSON");
        let decoded: Account = serde_json::from_str(&json).expect("account must round trip");
        assert_eq!(account, decoded);
    }

    #[test]
    fn borsh_roundtrip_for_nonce() {
        let nonce: Nonce = 7_u128.into();

        let borsh_serialized_nonce = borsh::to_vec(&nonce).unwrap();

        let nonce_restored = borsh::from_slice(&borsh_serialized_nonce).unwrap();

        assert_eq!(nonce, nonce_restored);
    }
}
