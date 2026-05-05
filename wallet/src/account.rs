use std::str::FromStr;

use base58::{FromBase58 as _, ToBase58 as _};
use derive_more::Display;
use nssa::AccountId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[display("{_0}")]
pub struct Label(String);

impl Label {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "Convenience for caller and negligible cost"
    )]
    #[must_use]
    pub fn new(label: impl ToString) -> Self {
        Self(label.to_string())
    }
}

impl FromStr for Label {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

#[derive(Debug, Display, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccountIdWithPrivacy {
    #[display("Public/{_0}")]
    Public(AccountId),
    #[display("Private/{_0}")]
    Private(AccountId),
}

#[derive(Debug, Error)]
pub enum AccountIdWithPrivacyParseError {
    #[error("Invalid format, expected 'Public/{{account_id}}' or 'Private/{{account_id}}'")]
    InvalidFormat,
    #[error("Invalid account id")]
    InvalidAccountId(#[from] nssa_core::account::AccountIdError),
}

impl FromStr for AccountIdWithPrivacy {
    type Err = AccountIdWithPrivacyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(stripped) = s.strip_prefix("Public/") {
            Ok(Self::Public(AccountId::from_str(stripped)?))
        } else if let Some(stripped) = s.strip_prefix("Private/") {
            Ok(Self::Private(AccountId::from_str(stripped)?))
        } else {
            Err(AccountIdWithPrivacyParseError::InvalidFormat)
        }
    }
}

/// Human-readable representation of an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanReadableAccount {
    balance: u128,
    program_owner: String,
    data: String,
    nonce: u128,
}

impl FromStr for HumanReadableAccount {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map_err(Into::into)
    }
}

impl std::fmt::Display for HumanReadableAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(self).map_err(|_err| std::fmt::Error)?;
        write!(f, "{json}")
    }
}

impl From<nssa::Account> for HumanReadableAccount {
    fn from(account: nssa::Account) -> Self {
        let program_owner = account
            .program_owner
            .iter()
            .flat_map(|n| n.to_le_bytes())
            .collect::<Vec<u8>>()
            .to_base58();
        let data = hex::encode(account.data);
        Self {
            balance: account.balance,
            program_owner,
            data,
            nonce: account.nonce.0,
        }
    }
}

impl From<HumanReadableAccount> for nssa::Account {
    fn from(account: HumanReadableAccount) -> Self {
        let mut program_owner_bytes = [0_u8; 32];
        let decoded_program_owner = account
            .program_owner
            .from_base58()
            .expect("Invalid base58 in HumanReadableAccount.program_owner");
        assert!(
            decoded_program_owner.len() == 32,
            "HumanReadableAccount.program_owner must decode to exactly 32 bytes"
        );
        program_owner_bytes.copy_from_slice(&decoded_program_owner);

        let mut program_owner = [0_u32; 8];
        for (index, chunk) in program_owner_bytes.chunks_exact(4).enumerate() {
            let chunk: [u8; 4] = chunk
                .try_into()
                .expect("chunk length is guaranteed to be 4");
            program_owner[index] = u32::from_le_bytes(chunk);
        }

        let data = hex::decode(&account.data).expect("Invalid hex in HumanReadableAccount.data");
        let data = data
            .try_into()
            .expect("Invalid account data: exceeds maximum allowed size");

        Self {
            balance: account.balance,
            program_owner,
            data,
            nonce: nssa_core::account::Nonce(account.nonce),
        }
    }
}
