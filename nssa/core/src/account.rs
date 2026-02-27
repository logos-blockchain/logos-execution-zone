use std::{fmt::Display, str::FromStr};

use base58::{FromBase58, ToBase58};
use borsh::{BorshDeserialize, BorshSerialize};
pub use data::Data;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::program::ProgramId;

pub mod data;

pub type Nonce = u128;

/// Account to be used both in public and private contexts
#[derive(
    Default, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Account {
    pub program_owner: ProgramId,
    pub balance: u128,
    pub data: Data,
    pub nonce: Nonce,
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let program_owner_hex: String = self
            .program_owner
            .iter()
            .flat_map(|n| n.to_le_bytes())
            .map(|b| format!("{b:02x}"))
            .collect();
        f.debug_struct("Account")
            .field("program_owner", &program_owner_hex)
            .field("balance", &self.balance)
            .field("data", &self.data)
            .field("nonce", &self.nonce)
            .finish()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
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
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(any(feature = "host", test), derive(PartialOrd, Ord))]
pub struct AccountId {
    value: [u8; 32],
}

impl std::fmt::Debug for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value.to_base58())
    }
}

impl AccountId {
    pub fn new(value: [u8; 32]) -> Self {
        Self { value }
    }

    pub fn value(&self) -> &[u8; 32] {
        &self.value
    }

    pub fn into_value(self) -> [u8; 32] {
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
        let mut value = [0u8; 32];
        value.copy_from_slice(&bytes);
        Ok(AccountId { value })
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
    fn test_zero_balance_account_data_creation() {
        let new_acc = Account::default();

        assert_eq!(new_acc.balance, 0);
    }

    #[test]
    fn test_zero_nonce_account_data_creation() {
        let new_acc = Account::default();

        assert_eq!(new_acc.nonce, 0);
    }

    #[test]
    fn test_empty_data_account_data_creation() {
        let new_acc = Account::default();

        assert!(new_acc.data.is_empty());
    }

    #[test]
    fn test_default_program_owner_account_data_creation() {
        let new_acc = Account::default();

        assert_eq!(new_acc.program_owner, DEFAULT_PROGRAM_ID);
    }

    #[cfg(feature = "host")]
    #[test]
    fn test_account_with_metadata_constructor() {
        let account = Account {
            program_owner: [1, 2, 3, 4, 5, 6, 7, 8],
            balance: 1337,
            data: b"testing_account_with_metadata_constructor"
                .to_vec()
                .try_into()
                .unwrap(),
            nonce: 0xdeadbeef,
        };
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
        assert_eq!(account_id.value, [0u8; 32]);
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
}
