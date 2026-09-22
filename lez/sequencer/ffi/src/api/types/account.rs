use std::collections::BTreeMap;

use lee::{Account, AccountData, AccountId, ShardData};

use crate::{
    OperationStatus,
    api::types::{FfiAccountId, FfiBytes32, FfiU128, FfiVec, vectors::FfiVecU8},
};

#[repr(C)]
pub struct FfiAccountData {
    /// Balance as little-endian [u8; 16].
    pub balance: FfiU128,
    /// Account shards keys.
    pub account_data_keys: FfiVec<FfiAccountId>,
    /// Account shards values (guaranteed to have same amount of entries as `account_data_keys`).
    pub account_data_values: FfiVec<FfiVecU8>,
}

impl From<AccountData> for FfiAccountData {
    fn from(value: AccountData) -> Self {
        let AccountData { balance, shards } = value;

        let acc_data_keys = shards.keys().copied().map(Into::into).collect::<Vec<_>>();
        let acc_data_values = shards
            .values()
            .cloned()
            .map(ShardData::into_inner)
            .map(Into::into)
            .collect::<Vec<_>>();

        Self {
            balance: balance.into(),
            account_data_keys: acc_data_keys.into(),
            account_data_values: acc_data_values.into(),
        }
    }
}

impl TryFrom<FfiAccountData> for AccountData {
    type Error = OperationStatus;

    fn try_from(value: FfiAccountData) -> Result<Self, Self::Error> {
        let keys_ffi: Vec<_> = value.account_data_keys.into();
        let keys_std: Vec<AccountId> = keys_ffi.into_iter().map(Into::into).collect();

        let values_ffi: Vec<_> = value.account_data_values.into();
        let values_std_raw: Vec<Vec<u8>> = values_ffi.into_iter().map(Into::into).collect();

        if values_std_raw.len() != keys_std.len() {
            log::error!(
                "Failed to cast `FfiAccount` into `Account`, err: Keys and values length mismatch"
            );
            return Err(OperationStatus::CastError);
        }

        let mut values_std = vec![];

        for raw_shard in values_std_raw {
            let shard: ShardData = raw_shard.try_into().map_err(|e| {
                log::error!("Failed to cast `FfiAccount` into `Account`, err: {e}");
                OperationStatus::CastError
            })?;

            values_std.push(shard);
        }

        Ok(Self {
            balance: value.balance.into(),
            shards: keys_std
                .into_iter()
                .zip(values_std)
                .collect::<BTreeMap<_, _>>(),
        })
    }
}

/// Account data structure - C-compatible version of lee Account.
///
/// Note: `balance` and `nonce` are u128 values represented as little-endian
/// byte arrays since C doesn't have native u128 support.
#[repr(C)]
pub struct FfiAccount {
    /// Account data struct.
    pub account_data: FfiAccountData,
    /// Nonce as little-endian [u8; 16].
    pub nonce: FfiU128,
}

// Helper functions to convert between Rust and FFI types

impl From<&lee::AccountId> for FfiBytes32 {
    fn from(id: &lee::AccountId) -> Self {
        Self::from_account_id(id)
    }
}

impl From<lee::Account> for FfiAccount {
    fn from(value: lee::Account) -> Self {
        let lee::Account { data, nonce } = value;

        Self {
            account_data: data.into(),
            nonce: nonce.0.into(),
        }
    }
}

impl TryFrom<FfiAccount> for Account {
    type Error = OperationStatus;

    fn try_from(value: FfiAccount) -> Result<Self, Self::Error> {
        let FfiAccount {
            account_data,
            nonce,
        } = value;

        Ok(Self {
            nonce: Into::<u128>::into(nonce).into(),
            data: account_data.try_into()?,
        })
    }
}

/// Frees the resources associated with the given ffi account.
///
/// Takes ownership of the whole allocation produced by a `query_*` call: the
/// outer `Box<FfiAccount>` (the `PointerResult.value` pointer) *and* its inner
/// data buffer. Passing the struct by value previously freed only the inner
/// buffer and leaked the outer box.
///
/// # Arguments
///
/// - `val`: The `*mut FfiAccount` returned in `PointerResult.value`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a pointer to an `FfiAccount` produced by this library and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_free_ffi_account(val: *mut FfiAccount) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then convert to drop the inner data buffer.
    let boxed = unsafe { Box::from_raw(val) };

    let orig_val_res: Result<Account, OperationStatus> = (*boxed)
        .try_into()
        .inspect_err(|_| log::error!("Failed to cast `FfiAccount` into `Account`"));

    if let Ok(orig_val) = orig_val_res {
        drop(orig_val);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lee::{Account, AccountData, AccountId, ShardData};
    use lee_core::account::Nonce;

    use crate::api::types::account::FfiAccount;

    #[test]
    fn account_roundtrip() {
        let mut shards = BTreeMap::new();

        shards.insert(
            AccountId::new([42; 32]),
            ShardData::try_from(vec![1, 1, 1, 1]).expect("Must fit"),
        );
        shards.insert(
            AccountId::new([43; 32]),
            ShardData::try_from(vec![2, 2, 2, 2]).expect("Must fit"),
        );
        shards.insert(
            AccountId::new([44; 32]),
            ShardData::try_from(vec![3, 3, 3, 3]).expect("Must fit"),
        );

        let account_std = Account {
            nonce: Nonce::from(5),
            data: AccountData {
                balance: 10,
                shards,
            },
        };

        let ffi_account: FfiAccount = account_std.clone().into();
        let account_std_trip: Account = ffi_account.try_into().expect("Must be castable");

        assert_eq!(account_std_trip, account_std);
    }
}
