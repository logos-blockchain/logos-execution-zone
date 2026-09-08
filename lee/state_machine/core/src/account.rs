use std::{collections::BTreeMap, fmt::Display, str::FromStr};

use base58::{FromBase58 as _, ToBase58 as _};
use borsh::{BorshDeserialize, BorshSerialize};
pub use data::Data;
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use thiserror::Error;

use crate::{NullifierSecretKey, program::AccountStateDiff};

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
/// A base-fee price or tip, in atomic units; fits `u64` by the per-block gas caps
/// (balances and totals are [`Balance`], `u128`).
pub type Fee = u64;
/// A gas amount (execution or storage work), bounded per block.
pub type Gas = u64;
/// A raw zkVM execution cycle count or budget, before it is priced into [`Gas`].
pub type Cycles = u64;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum BalanceDiff {
    Add(Balance),
    Sub(Balance),
}

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceDiffError {
    #[error("balance overflow")]
    Overflow,
    #[error("insufficient balance")]
    InsufficientBalance,
}

/// Account to be used both in public and private contexts.
#[derive(
    Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Account {
    pub nonce: Nonce,
    pub data: AccountData,
}

impl Account {
    #[must_use]
    pub fn with_shard(mut self, program: AccountId, data: Data) -> Self {
        self.data.set_shard(program, data);
        self
    }
}

#[cfg(any(test, feature = "test_utils"))]
impl Account {
    #[must_use]
    pub fn funded(balance: Balance) -> Self {
        Self {
            data: AccountData {
                balance,
                ..AccountData::default()
            },
            ..Self::default()
        }
    }
}

/// An account's balance and program shards.
#[derive(
    Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct AccountData {
    pub balance: Balance,
    pub shards: BTreeMap<AccountId, Data>,
}

impl AccountData {
    #[must_use]
    pub fn shard(&self, program: AccountId) -> &Data {
        const EMPTY: &Data = &Data::empty();
        self.shards.get(&program).unwrap_or(EMPTY)
    }

    pub fn set_shard(&mut self, program: AccountId, data: Data) {
        if data.is_empty() {
            self.shards.remove(&program);
        } else {
            self.shards.insert(program, data);
        }
    }

    #[must_use]
    pub fn with_shard(mut self, program: AccountId, data: Data) -> Self {
        self.set_shard(program, data);
        self
    }

    pub fn apply_diff(&mut self, diff: &AccountStateDiff) -> Result<(), BalanceDiffError> {
        self.balance = apply_balance_diff(diff.pre_state.balance, Some(diff.post_balance_diff))?;
        if let Some((program, pre_data)) = &diff.pre_state.shard {
            self.set_shard(
                *program,
                diff.post_data.clone().unwrap_or_else(|| pre_data.clone()),
            );
        }
        Ok(())
    }

    /// Returns the balance and requested shards, with empty data for missing shards.
    #[must_use]
    pub fn project(&self, program_account_ids: impl IntoIterator<Item = AccountId>) -> Self {
        Self {
            balance: self.balance,
            shards: program_account_ids
                .into_iter()
                .map(|program| (program, self.shard(program).clone()))
                .collect(),
        }
    }

    /// Updates the balance and supplied shards. Empty data removes a shard.
    pub fn apply(&mut self, projection: &Self) {
        self.balance = projection.balance;
        for (program, data) in &projection.shards {
            self.set_shard(*program, data.clone());
        }
    }
}

/// Selects an account's balance and optionally one program shard.
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct ProgramShardSelector {
    pub account_id: AccountId,
    pub program_account_id: Option<AccountId>,
}

impl ProgramShardSelector {
    #[must_use]
    pub const fn new(account_id: AccountId, program_account_id: AccountId) -> Self {
        Self {
            account_id,
            program_account_id: Some(program_account_id),
        }
    }

    #[must_use]
    pub const fn balance_only(account_id: AccountId) -> Self {
        Self {
            account_id,
            program_account_id: None,
        }
    }
}

/// An account seen as an input to an LEE program.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AccountInput {
    pub account_id: AccountId,
    pub is_authorized: bool,
    pub balance: Balance,
    pub shard: Option<(AccountId, Data)>,
}

impl AccountInput {
    #[must_use]
    pub const fn with_shard(
        account_id: AccountId,
        is_authorized: bool,
        balance: Balance,
        program_account_id: AccountId,
        data: Data,
    ) -> Self {
        Self {
            account_id,
            is_authorized,
            balance,
            shard: Some((program_account_id, data)),
        }
    }

    #[must_use]
    pub const fn balance_only(
        account_id: AccountId,
        is_authorized: bool,
        balance: Balance,
    ) -> Self {
        Self {
            account_id,
            is_authorized,
            balance,
            shard: None,
        }
    }

    #[must_use]
    pub fn at(
        shard_selector: ProgramShardSelector,
        is_authorized: bool,
        data: &AccountData,
    ) -> Self {
        Self {
            account_id: shard_selector.account_id,
            is_authorized,
            balance: data.balance,
            shard: shard_selector
                .program_account_id
                .map(|program| (program, data.shard(program).clone())),
        }
    }

    #[must_use]
    pub fn program_account_id(&self) -> Option<AccountId> {
        self.shard.as_ref().map(|(program, _)| *program)
    }

    /// Returns the shard data. Panics unless the input selects `program`'s shard.
    #[must_use]
    pub fn shard_of(&self, program: AccountId) -> &Data {
        let (selected, data) = self.shard.as_ref().expect("AccountInput carries no shard");
        assert_eq!(
            *selected, program,
            "AccountInput carries another program's shard"
        );
        data
    }
}

impl From<&AccountInput> for ProgramShardSelector {
    fn from(input: &AccountInput) -> Self {
        Self {
            account_id: input.account_id,
            program_account_id: input.program_account_id(),
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

pub fn apply_balance_diff(
    current: Balance,
    diff: Option<BalanceDiff>,
) -> Result<Balance, BalanceDiffError> {
    match diff {
        None => Ok(current),
        Some(BalanceDiff::Add(amount)) => current
            .checked_add(amount)
            .ok_or(BalanceDiffError::Overflow),
        Some(BalanceDiff::Sub(amount)) => current
            .checked_sub(amount)
            .ok_or(BalanceDiffError::InsufficientBalance),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_balance_account_data_creation() {
        let new_acc = Account::default();

        assert_eq!(new_acc.data.balance, 0);
    }

    #[test]
    fn zero_nonce_account_data_creation() {
        let new_acc = Account::default();

        assert_eq!(new_acc.nonce.0, 0);
    }

    #[test]
    fn default_account_has_no_shards() {
        let new_acc = Account::default();

        assert!(new_acc.data.shards.is_empty());
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
    fn borsh_roundtrip_for_nonce() {
        let nonce: Nonce = 7_u128.into();

        let borsh_serialized_nonce = borsh::to_vec(&nonce).unwrap();

        let nonce_restored = borsh::from_slice(&borsh_serialized_nonce).unwrap();

        assert_eq!(nonce, nonce_restored);
    }

    #[test]
    fn apply_balance_diff_none_is_noop() {
        let result = apply_balance_diff(10, None);
        assert_eq!(result, Ok(10));
    }

    #[test]
    fn apply_balance_diff_add_succeeds() {
        let result = apply_balance_diff(10, Some(BalanceDiff::Add(5)));
        assert_eq!(result, Ok(15));
    }

    #[test]
    fn apply_balance_diff_add_zero_is_noop() {
        let result = apply_balance_diff(10, Some(BalanceDiff::Add(0)));
        assert_eq!(result, Ok(10));
    }

    #[test]
    fn apply_balance_diff_add_overflow_is_rejected() {
        let result = apply_balance_diff(Balance::MAX, Some(BalanceDiff::Add(1)));
        assert_eq!(result, Err(BalanceDiffError::Overflow));
    }

    #[test]
    fn apply_balance_diff_sub_succeeds() {
        let result = apply_balance_diff(10, Some(BalanceDiff::Sub(5)));
        assert_eq!(result, Ok(5));
    }

    #[test]
    fn apply_balance_diff_sub_zero_is_noop() {
        let result = apply_balance_diff(10, Some(BalanceDiff::Sub(0)));
        assert_eq!(result, Ok(10));
    }

    #[test]
    fn apply_balance_diff_sub_down_to_exactly_zero_succeeds() {
        let result = apply_balance_diff(10, Some(BalanceDiff::Sub(10)));
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn apply_balance_diff_sub_insufficient_balance_is_rejected() {
        let result = apply_balance_diff(10, Some(BalanceDiff::Sub(11)));
        assert_eq!(result, Err(BalanceDiffError::InsufficientBalance));
    }

    #[test]
    fn serde_roundtrip_for_balance_diff() {
        let diff = BalanceDiff::Add(7);

        let serde_serialized_diff = serde_json::to_vec(&diff).unwrap();
        let diff_restored = serde_json::from_slice(&serde_serialized_diff).unwrap();

        assert_eq!(diff, diff_restored);
    }

    #[test]
    fn borsh_roundtrip_for_balance_diff() {
        let diff = BalanceDiff::Sub(7);

        let borsh_serialized_diff = borsh::to_vec(&diff).unwrap();
        let diff_restored = borsh::from_slice(&borsh_serialized_diff).unwrap();

        assert_eq!(diff, diff_restored);
    }

    #[test]
    fn apply_diff_prunes_an_emptied_shard() {
        let program = AccountId::new([3; 32]);
        let mut account =
            Account::funded(10).with_shard(program, b"record".to_vec().try_into().unwrap());

        account
            .data
            .apply_diff(&AccountStateDiff::new(
                AccountInput::with_shard(
                    AccountId::new([1; 32]),
                    true,
                    10,
                    program,
                    b"record".to_vec().try_into().unwrap(),
                ),
                BalanceDiff::Sub(3),
                Data::empty(),
            ))
            .unwrap();

        assert!(!account.data.shards.contains_key(&program));
        assert_eq!(account, Account::funded(7));
    }

    #[test]
    fn set_shard_keeps_the_encoding_canonical() {
        let program = AccountId::new([3; 32]);
        let mut account = Account::default();

        account
            .data
            .set_shard(program, b"record".to_vec().try_into().unwrap());
        account.data.set_shard(program, Data::empty());

        assert_eq!(account.to_bytes(), Account::default().to_bytes());
    }

    #[test]
    fn input_at_reads_a_vacant_shard_as_empty() {
        let account_id = AccountId::new([1; 32]);
        let program = AccountId::new([3; 32]);
        let data = AccountData {
            balance: 42,
            ..AccountData::default()
        };

        let input = AccountInput::at(ProgramShardSelector::new(account_id, program), true, &data);

        assert_eq!(input.balance, 42);
        assert_eq!(input.program_account_id(), Some(program));
        assert!(input.shard_of(program).is_empty());
    }

    #[test]
    fn input_at_of_a_balance_only_shard_selector_carries_no_shard() {
        let account_id = AccountId::new([1; 32]);
        let data = AccountData {
            balance: 42,
            ..AccountData::default()
        }
        .with_shard(
            AccountId::new([3; 32]),
            b"record".to_vec().try_into().unwrap(),
        );

        let input = AccountInput::at(ProgramShardSelector::balance_only(account_id), false, &data);

        assert_eq!(input.balance, 42);
        assert_eq!(input.program_account_id(), None);
        assert!(input.shard.is_none());
    }

    #[test]
    fn shard_selector_of_an_input_drops_what_it_holds() {
        let account_id = AccountId::new([1; 32]);
        let program = AccountId::new([3; 32]);
        let named = AccountInput::with_shard(
            account_id,
            true,
            5,
            program,
            b"record".to_vec().try_into().unwrap(),
        );
        let balance_only = AccountInput::balance_only(account_id, true, 5);

        assert_eq!(
            ProgramShardSelector::from(&named),
            ProgramShardSelector::new(account_id, program)
        );
        assert_eq!(
            ProgramShardSelector::from(&balance_only),
            ProgramShardSelector::balance_only(account_id)
        );
    }

    #[test]
    fn project_reads_absent_shards_as_empty() {
        let held = AccountId::new([3; 32]);
        let absent = AccountId::new([4; 32]);
        let data = AccountData {
            balance: 9,
            ..AccountData::default()
        }
        .with_shard(held, b"record".to_vec().try_into().unwrap());

        let projection = data.project([held, absent]);

        assert_eq!(projection.balance, 9);
        assert_eq!(projection.shards.get(&absent), Some(&Data::empty()));
        assert_eq!(projection.shards.len(), 2);
    }

    #[test]
    fn apply_keeps_the_nonce_and_prunes_emptied_shards() {
        let program = AccountId::new([3; 32]);
        let mut account = Account {
            nonce: Nonce(7),
            ..Account::funded(9).with_shard(program, b"record".to_vec().try_into().unwrap())
        };

        account.data.apply(&AccountData {
            balance: 1,
            shards: [(program, Data::empty())].into(),
        });

        assert_eq!(account.nonce, Nonce(7));
        assert_eq!(account.data.balance, 1);
        assert!(account.data.shards.is_empty());
    }

    #[test]
    fn project_then_apply_is_identity_on_the_touched_shards() {
        let touched = AccountId::new([3; 32]);
        let untouched = AccountId::new([4; 32]);
        let data = AccountData {
            balance: 9,
            ..AccountData::default()
        }
        .with_shard(touched, b"record".to_vec().try_into().unwrap())
        .with_shard(untouched, b"other".to_vec().try_into().unwrap());

        let mut applied = data.clone();
        applied.apply(&data.project([touched]));

        assert_eq!(applied, data);
    }

    #[test]
    fn an_account_json_round_trip_holds_the_largest_balance_and_nonce() {
        let account = Account {
            nonce: Nonce(u128::MAX),
            ..Account::funded(u128::MAX).with_shard(
                AccountId::new([3; 32]),
                b"record".to_vec().try_into().unwrap(),
            )
        };

        let json = serde_json::to_string(&account).unwrap();
        let restored: Account = serde_json::from_str(&json).unwrap();

        assert_eq!(account, restored);
        assert_eq!(restored.nonce, Nonce(u128::MAX));
        assert_eq!(restored.data.balance, u128::MAX);
    }

    #[test]
    fn an_account_serializes_with_its_data_nested() {
        let account = Account {
            nonce: Nonce(7),
            ..Account::funded(9)
        };

        assert_eq!(
            serde_json::to_string(&account).unwrap(),
            r#"{"nonce":7,"data":{"balance":9,"shards":{}}}"#
        );
    }
}
