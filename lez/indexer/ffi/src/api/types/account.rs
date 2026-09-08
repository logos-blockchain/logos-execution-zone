use std::collections::BTreeMap;

use crate::api::types::{FfiBytes32, FfiU128};

/// One program's shard on an account.
#[repr(C)]
pub struct FfiShard {
    pub program: FfiBytes32,
    /// Pointer to shard data bytes.
    pub data: *mut u8,
    /// Length of shard data.
    pub data_len: usize,
    /// Capacity of shard data.
    pub data_cap: usize,
}

/// Account data structure - C-compatible version of lee Account.
///
/// Note: `balance` and `nonce` are u128 values represented as little-endian
/// byte arrays since C doesn't have native u128 support.
#[repr(C)]
pub struct FfiAccount {
    /// Balance as little-endian [u8; 16].
    pub balance: FfiU128,
    /// Nonce as little-endian [u8; 16].
    pub nonce: FfiU128,
    /// Pointer to the account's shards.
    pub shards: *mut FfiShard,
    /// Number of shards.
    pub shards_len: usize,
}

/// An account's balance and program shards.
#[repr(C)]
pub struct FfiAccountData {
    /// Balance as little-endian [u8; 16].
    pub balance: FfiU128,
    /// Pointer to the account's shards.
    pub shards: *mut FfiShard,
    /// Number of shards.
    pub shards_len: usize,
}

// Helper functions to convert between Rust and FFI types

impl From<(lee::AccountId, lee::Data)> for FfiShard {
    fn from((program, data): (lee::AccountId, lee::Data)) -> Self {
        let (data, data_len, data_cap) = data.into_inner().into_raw_parts();
        Self {
            program: FfiBytes32::from_account_id(&program),
            data,
            data_len,
            data_cap,
        }
    }
}

impl From<&lee::AccountId> for FfiBytes32 {
    fn from(id: &lee::AccountId) -> Self {
        Self::from_account_id(id)
    }
}

impl From<lee::Account> for FfiAccount {
    fn from(value: lee::Account) -> Self {
        let lee::Account {
            nonce,
            data: lee::AccountData { balance, shards },
        } = value;

        let (shards, shards_len) = shards_into_raw(shards);

        Self {
            balance: balance.into(),
            nonce: nonce.0.into(),
            shards,
            shards_len,
        }
    }
}

impl From<lee::AccountData> for FfiAccountData {
    fn from(value: lee::AccountData) -> Self {
        let lee::AccountData { balance, shards } = value;

        let (shards, shards_len) = shards_into_raw(shards);

        Self {
            balance: balance.into(),
            shards,
            shards_len,
        }
    }
}

impl From<FfiAccount> for indexer_service_protocol::Account {
    fn from(value: FfiAccount) -> Self {
        let FfiAccount {
            balance,
            nonce,
            shards,
            shards_len,
        } = value;

        Self {
            nonce: nonce.into(),
            data: indexer_service_protocol::AccountData {
                balance: balance.into(),
                shards: unsafe { shards_from_raw(shards, shards_len) },
            },
        }
    }
}

impl From<&FfiAccount> for indexer_service_protocol::Account {
    fn from(value: &FfiAccount) -> Self {
        let &FfiAccount {
            balance,
            nonce,
            shards,
            shards_len,
        } = value;

        Self {
            nonce: nonce.into(),
            data: indexer_service_protocol::AccountData {
                balance: balance.into(),
                shards: unsafe { shards_from_raw(shards, shards_len) },
            },
        }
    }
}

impl From<FfiAccountData> for indexer_service_protocol::AccountData {
    fn from(value: FfiAccountData) -> Self {
        let FfiAccountData {
            balance,
            shards,
            shards_len,
        } = value;

        Self {
            balance: balance.into(),
            shards: unsafe { shards_from_raw(shards, shards_len) },
        }
    }
}

/// Converts shards into a boxed slice and returns its pointer and length.
fn shards_into_raw(shards: BTreeMap<lee::AccountId, lee::Data>) -> (*mut FfiShard, usize) {
    let boxed: Box<[FfiShard]> = shards.into_iter().map(FfiShard::from).collect();
    let len = boxed.len();
    (Box::into_raw(boxed).cast::<FfiShard>(), len)
}

/// Reclaims a shard buffer produced by [`shards_into_raw`].
///
/// # Safety
///
/// `ptr`/`len` must be exactly the pair returned by a prior [`shards_into_raw`] call, not
/// already reclaimed.
unsafe fn shards_from_raw(
    ptr: *mut FfiShard,
    len: usize,
) -> BTreeMap<indexer_service_protocol::AccountId, indexer_service_protocol::Data> {
    let boxed = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) };
    Vec::from(boxed)
        .into_iter()
        .map(|shard| {
            let FfiShard {
                program,
                data,
                data_len,
                data_cap,
            } = shard;
            (
                indexer_service_protocol::AccountId {
                    value: program.data,
                },
                indexer_service_protocol::Data(unsafe {
                    Vec::from_raw_parts(data, data_len, data_cap)
                }),
            )
        })
        .collect()
}

/// Frees an account, its shard array, and each shard's data buffer.
///
/// # Safety
///
/// `val` must be null or an unfreed `PointerResult.value` from an account query.
/// Its shard array and data buffers must remain valid and owned by the account.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ffi_account(val: *mut FfiAccount) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then convert to drop the shard array and its buffers.
    let boxed = unsafe { Box::from_raw(val) };
    let orig_val: indexer_service_protocol::Account = (*boxed).into();
    drop(orig_val);
}
