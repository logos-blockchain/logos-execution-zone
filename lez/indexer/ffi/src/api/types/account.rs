use crate::api::types::{FfiBytes32, FfiU128};

/// Account data structure - C-compatible version of lee Account.
///
/// Note: `balance` and `nonce` are u128 values represented as little-endian
/// byte arrays since C doesn't have native u128 support.
#[repr(C)]
pub struct FfiAccount {
    pub program_owner: FfiBytes32,
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

impl From<&lee::AccountId> for FfiBytes32 {
    fn from(id: &lee::AccountId) -> Self {
        Self::from_account_id(id)
    }
}

impl From<lee::Account> for FfiAccount {
    fn from(value: lee::Account) -> Self {
        let lee::Account {
            program_owner,
            balance,
            data,
            nonce,
        } = value;

        let (data, data_len, data_cap) = data.into_inner().into_raw_parts();

        Self {
            program_owner: FfiBytes32::from_account_id(&program_owner),
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
            program_owner: indexer_service_protocol::AccountId {
                value: program_owner.data,
            },
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
            program_owner: indexer_service_protocol::AccountId {
                value: program_owner.data,
            },
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
pub unsafe extern "C" fn free_ffi_account(val: *mut FfiAccount) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then convert to drop the inner data buffer.
    let boxed = unsafe { Box::from_raw(val) };
    let orig_val: indexer_service_protocol::Account = (*boxed).into();
    drop(orig_val);
}
