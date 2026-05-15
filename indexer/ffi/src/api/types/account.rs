use indexer_service_protocol::ProgramId;

use crate::api::types::{FfiBytes32, FfiProgramId, FfiU128};

/// Account data structure - C-compatible version of nssa Account.
///
/// Note: `balance` and `nonce` are u128 values represented as little-endian
/// byte arrays since C doesn't have native u128 support.
#[repr(C)]
pub struct FfiAccount {
    pub program_owner: FfiProgramId,
    /// Balance as little-endian [u8; 16].
    pub balance: FfiU128,
    /// Pointer to account data bytes.
    pub data: *mut u8,
    /// Length of account data.
    pub data_len: usize,
    /// Capacity of account data.
    pub data_cap: usize,
    /// Nonce as little-endian [u8; 16].
    pub nonce: FfiU128,
}

// Helper functions to convert between Rust and FFI types

impl From<&nssa::AccountId> for FfiBytes32 {
    fn from(id: &nssa::AccountId) -> Self {
        Self::from_account_id(id)
    }
}

impl From<nssa::Account> for FfiAccount {
    fn from(value: nssa::Account) -> Self {
        let nssa::Account {
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

impl From<FfiAccount> for indexer_service_protocol::Account {
    fn from(value: FfiAccount) -> Self {
        let FfiAccount {
            program_owner,
            balance,
            data,
            data_cap,
            data_len,
            nonce,
        } = value;

        Self {
            program_owner: ProgramId(program_owner.data),
            balance: balance.into(),
            data: indexer_service_protocol::Data(unsafe {
                Vec::from_raw_parts(data, data_len, data_cap)
            }),
            nonce: nonce.into(),
        }
    }
}

impl From<&FfiAccount> for indexer_service_protocol::Account {
    fn from(value: &FfiAccount) -> Self {
        let &FfiAccount {
            program_owner,
            balance,
            data,
            data_cap,
            data_len,
            nonce,
        } = value;

        Self {
            program_owner: ProgramId(program_owner.data),
            balance: balance.into(),
            data: indexer_service_protocol::Data(unsafe {
                Vec::from_raw_parts(data, data_len, data_cap)
            }),
            nonce: nonce.into(),
        }
    }
}

/// Frees the resources associated with the given ffi account.
///
/// # Arguments
///
/// - `val`: An instance of `FfiAccount`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a valid instance of `FfiAccount`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ffi_account(val: FfiAccount) {
    let orig_val: indexer_service_protocol::Account = val.into();
    drop(orig_val);
}
