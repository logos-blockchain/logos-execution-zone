use std::{collections::BTreeMap, str::FromStr};

use derive_more::Display;
use lee::AccountId;
use lee_core::account::Slot;
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

impl AsRef<str> for Label {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for Label {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl From<&str> for Label {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for Label {
    fn from(value: String) -> Self {
        Self(value)
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
    InvalidAccountId(#[from] lee_core::account::AccountIdError),
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

/// Human-readable representation of a single program's slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanReadableSlot {
    balance: u128,
    data: String,
}

/// Human-readable representation of an account, with one entry per occupied slot keyed by the
/// owning program's [`AccountId`] rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanReadableAccount {
    nonce: u128,
    slots: BTreeMap<String, HumanReadableSlot>,
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

impl From<&Slot> for HumanReadableSlot {
    fn from(slot: &Slot) -> Self {
        Self {
            balance: slot.balance,
            data: hex::encode(&slot.data),
        }
    }
}

impl From<lee::Account> for HumanReadableAccount {
    fn from(account: lee::Account) -> Self {
        Self {
            nonce: account.nonce.0,
            slots: account
                .slots
                .iter()
                .map(|(&program, slot)| (program.to_string(), slot.into()))
                .collect(),
        }
    }
}

impl From<HumanReadableAccount> for lee::Account {
    fn from(account: HumanReadableAccount) -> Self {
        Self {
            nonce: lee_core::account::Nonce(account.nonce),
            slots: account
                .slots
                .into_iter()
                .map(|(program_id, slot)| {
                    let program_id: AccountId = program_id
                        .parse()
                        .expect("Invalid base58 in HumanReadableAccount slot key");
                    let data =
                        hex::decode(&slot.data).expect("Invalid hex in HumanReadableAccount.data");
                    let data = data
                        .try_into()
                        .expect("Invalid account data: exceeds maximum allowed size");

                    (
                        program_id,
                        Slot {
                            balance: slot.balance,
                            data,
                        },
                    )
                })
                .collect(),
        }
    }
}
