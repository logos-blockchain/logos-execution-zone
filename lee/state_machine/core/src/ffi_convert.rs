use ffi_core::api::types::{FfiBytes32, FfiProgramId, account::FfiAccount};

use crate::account::{Account, AccountId};

impl From<&AccountId> for FfiBytes32 {
    fn from(id: &AccountId) -> Self {
        Self { data: *id.value() }
    }
}

impl From<Account> for FfiAccount {
    fn from(value: Account) -> Self {
        let Account {
            program_owner,
            balance,
            data,
            nonce,
        } = value;

        let (data, data_len, data_cap) = data.into_inner().into_raw_parts();

        let program_owner = FfiProgramId {
            data: program_owner,
        };
        Self {
            program_owner,
            balance: balance.into(),
            data,
            data_len,
            data_cap,
            nonce: nonce.0.into(),
        }
    }
}