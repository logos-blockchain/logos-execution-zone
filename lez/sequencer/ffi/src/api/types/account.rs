use std::collections::BTreeMap;

use lee::{Account, AccountData, AccountId, ActorState};

use crate::{
    OperationStatus,
    api::types::{FfiAccountId, FfiOption, FfiU128, FfiVec, vectors::FfiVecU8},
};

#[repr(C)]
pub struct FfiAccountData {
    /// Account actor state keys.
    pub account_data_keys: FfiVec<FfiAccountId>,
    /// Account actor state values (guaranteed to have same amount of entries as
    /// `account_data_keys`).
    pub account_data_values: FfiVec<FfiVecU8>,
}

impl From<AccountData> for FfiAccountData {
    fn from(value: AccountData) -> Self {
        let AccountData { actor_states } = value;

        let acc_data_keys = actor_states
            .keys()
            .copied()
            .map(Into::into)
            .collect::<Vec<_>>();
        let acc_data_values = actor_states
            .values()
            .cloned()
            .map(ActorState::into_inner)
            .map(Into::into)
            .collect::<Vec<_>>();

        Self {
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

        Ok(Self {
            actor_states: keys_std
                .into_iter()
                .zip(values_std_raw.into_iter().map(ActorState::from))
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

/// Frees the resources associated with the given ffi account option.
///
/// Takes ownership of the whole allocation produced by a `query_*` call: the
/// outer `Box<FfiOption<FfiAccount>>` (the `PointerResult.value` pointer), the
/// inner `Box<FfiAccount>` (when present) and its data buffer.
///
/// # Arguments
///
/// - `val`: The `*mut FfiOption<FfiAccount>` returned in `PointerResult.value`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a pointer to an `FfiOption<FfiAccount>` produced by this library and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sequencer_ffi_free_ffi_account_opt(val: *mut FfiOption<FfiAccount>) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then the inner account box (if any), converting it to drop its data.
    let opt = unsafe { Box::from_raw(val) };
    if opt.is_some {
        let account = unsafe { Box::from_raw(opt.value) };
        let orig_val_res: Result<Account, OperationStatus> = (*account)
            .try_into()
            .inspect_err(|_| log::error!("Failed to cast `FfiAccount` into `Account`"));

        if let Ok(orig_val) = orig_val_res {
            drop(orig_val);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lee::{Account, AccountData, AccountId, ActorState};
    use lee_core::account::Nonce;

    use crate::api::types::account::FfiAccount;

    #[test]
    fn account_roundtrip() {
        let mut actor_states = BTreeMap::new();

        actor_states.insert(AccountId::new([42; 32]), ActorState::from(vec![1, 1, 1, 1]));
        actor_states.insert(AccountId::new([43; 32]), ActorState::from(vec![2, 2, 2, 2]));
        actor_states.insert(AccountId::new([44; 32]), ActorState::from(vec![3, 3, 3, 3]));

        let account_std = Account {
            nonce: Nonce::from(5),
            data: AccountData { actor_states },
        };

        let ffi_account: FfiAccount = account_std.clone().into();
        let account_std_trip: Account = ffi_account.try_into().expect("Must be castable");

        assert_eq!(account_std_trip, account_std);
    }
}
