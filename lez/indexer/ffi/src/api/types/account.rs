use std::collections::BTreeMap;

use crate::api::types::{FfiBytes32, FfiU128};

/// One program's shard on an account - C-compatible version of one entry in lee's
/// `Account.shards` / `AccountView.shards`.
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

/// An account minus its nonce, restricted to the namespaces a transaction touched -
/// C-compatible version of lee `AccountView`.
#[repr(C)]
pub struct FfiAccountView {
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
            balance,
            nonce,
            shards,
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

impl From<lee::AccountView> for FfiAccountView {
    fn from(value: lee::AccountView) -> Self {
        let lee::AccountView { balance, shards } = value;

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
            balance: balance.into(),
            nonce: nonce.into(),
            shards: unsafe { shards_from_raw(shards, shards_len) },
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
            balance: balance.into(),
            nonce: nonce.into(),
            shards: unsafe { shards_from_raw(shards, shards_len) },
        }
    }
}

impl From<FfiAccountView> for indexer_service_protocol::AccountView {
    fn from(value: FfiAccountView) -> Self {
        let FfiAccountView {
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

/// Moves `shards` into a freshly-allocated, exactly-sized buffer and returns its raw parts.
/// The absence of a capacity field is intentional: the buffer is always built here, fresh,
/// from an exact-size iterator, so `shards_len` alone is enough to reclaim it (see
/// [`shards_from_raw`]).
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

/// Frees the resources associated with the given ffi account.
///
/// Takes ownership of the whole allocation produced by a `query_*` call: the
/// outer `Box<FfiAccount>` (the `PointerResult.value` pointer), the shard
/// array, and each shard's data buffer.
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
    // Reclaim the outer box, then convert to drop the shard array and its buffers.
    let boxed = unsafe { Box::from_raw(val) };
    let orig_val: indexer_service_protocol::Account = (*boxed).into();
    drop(orig_val);
}
