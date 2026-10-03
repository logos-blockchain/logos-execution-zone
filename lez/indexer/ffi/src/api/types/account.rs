use std::collections::BTreeMap;

use crate::api::types::{FfiBytes32, FfiU128};

/// One program's actor state on an account.
#[repr(C)]
pub struct FfiActorState {
    pub program: FfiBytes32,
    /// Pointer to actor state data bytes.
    pub data: *mut u8,
    /// Length of actor state data.
    pub data_len: usize,
    /// Capacity of actor state data.
    pub data_cap: usize,
}

/// Account data structure - C-compatible version of lee Account.
///
/// Note: `nonce` is a u128 value represented as a little-endian byte array since C doesn't have
/// native u128 support. The native balance is the actor state of the native token program.
#[repr(C)]
pub struct FfiAccount {
    /// Nonce as little-endian [u8; 16].
    pub nonce: FfiU128,
    /// Pointer to the account's actor states.
    pub actor_states: *mut FfiActorState,
    /// Number of actor states.
    pub actor_states_len: usize,
}

// Helper functions to convert between Rust and FFI types

impl From<(lee::AccountId, lee::ActorState)> for FfiActorState {
    fn from((program, data): (lee::AccountId, lee::ActorState)) -> Self {
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
            data: lee::AccountData { actor_states },
        } = value;

        let (actor_states, actor_states_len) = actor_states_into_raw(actor_states);

        Self {
            nonce: nonce.0.into(),
            actor_states,
            actor_states_len,
        }
    }
}

impl From<FfiAccount> for indexer_service_protocol::Account {
    fn from(value: FfiAccount) -> Self {
        let FfiAccount {
            nonce,
            actor_states,
            actor_states_len,
        } = value;

        Self {
            nonce: nonce.into(),
            data: indexer_service_protocol::AccountData {
                actor_states: unsafe { actor_states_from_raw(actor_states, actor_states_len) },
            },
        }
    }
}

impl From<&FfiAccount> for indexer_service_protocol::Account {
    fn from(value: &FfiAccount) -> Self {
        let &FfiAccount {
            nonce,
            actor_states,
            actor_states_len,
        } = value;

        Self {
            nonce: nonce.into(),
            data: indexer_service_protocol::AccountData {
                actor_states: unsafe { actor_states_from_raw(actor_states, actor_states_len) },
            },
        }
    }
}

/// Converts actor states into a boxed slice and returns its pointer and length.
fn actor_states_into_raw(
    actor_states: BTreeMap<lee::AccountId, lee::ActorState>,
) -> (*mut FfiActorState, usize) {
    let boxed: Box<[FfiActorState]> = actor_states.into_iter().map(FfiActorState::from).collect();
    let len = boxed.len();
    (Box::into_raw(boxed).cast::<FfiActorState>(), len)
}

/// Reclaims an actor state buffer produced by [`actor_states_into_raw`].
///
/// # Safety
///
/// `ptr`/`len` must be exactly the pair returned by a prior [`actor_states_into_raw`] call, not
/// already reclaimed.
unsafe fn actor_states_from_raw(
    ptr: *mut FfiActorState,
    len: usize,
) -> BTreeMap<indexer_service_protocol::AccountId, indexer_service_protocol::ActorState> {
    let boxed = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) };
    Vec::from(boxed)
        .into_iter()
        .map(|actor_state| {
            let FfiActorState {
                program,
                data,
                data_len,
                data_cap,
            } = actor_state;
            (
                indexer_service_protocol::AccountId {
                    value: program.data,
                },
                indexer_service_protocol::ActorState(unsafe {
                    Vec::from_raw_parts(data, data_len, data_cap)
                }),
            )
        })
        .collect()
}

/// Frees an account, its actor state array, and each actor state's data buffer.
///
/// # Safety
///
/// `val` must be null or an unfreed `PointerResult.value` from an account query.
/// Its actor state array and data buffers must remain valid and owned by the account.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ffi_account(val: *mut FfiAccount) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }
    // Reclaim the outer box, then convert to drop the actor state array and its buffers.
    let boxed = unsafe { Box::from_raw(val) };
    let orig_val: indexer_service_protocol::Account = (*boxed).into();
    drop(orig_val);
}
