use std::ffi::{CString, c_char};

use common::HashType;
use lee::{AccountId, ProgramId, PublicKey, Signature};
use lee_core::account::Nonce;
use sequencer_executor_actor::protocol::GetStatusReply;
use sequencer_storage_actor::actor::event_filter::Selector;

use crate::OperationStatus;

pub mod account;
pub mod block;
pub mod event;
pub mod transaction;
pub mod vectors;

/// Enum which represents current sequencer state.
#[repr(C)]
pub enum FfiSequencerSyncStatus {
    Synced = 0x0,
}

/// Struct which represents sequencer status on the moment of a call.
#[repr(C)]
pub struct FfiSequencerStatus {
    pub sync_status: FfiSequencerSyncStatus,
    pub chain_height: u64,
    pub failed_attempts: u32,
    pub blocked_attempts_count: u32,
    pub blocked_attempts_behind: FfiOption<[u8; 32]>,
    /// Complex structure which contains error object.
    /// No reason to keep in non-serialized state.
    pub stall_reason: *mut c_char,
}

impl TryFrom<GetStatusReply> for FfiSequencerStatus {
    type Error = OperationStatus;

    fn try_from(value: GetStatusReply) -> Result<Self, Self::Error> {
        let json = match serde_json::to_string(&value.stall_reason) {
            Ok(json) => json,
            Err(e) => {
                log::error!("Failed to serialize stall reason: {e}");
                return Err(OperationStatus::CastError);
            }
        };

        let stall_reason = match CString::new(json) {
            Ok(c_string) => CString::into_raw(c_string),
            Err(e) => {
                log::error!("Stall reason JSON contained an interior nul byte: {e}");
                return Err(OperationStatus::CastError);
            }
        };

        Ok(Self {
            // TODO: Figure out how to represent sequencer sync status.
            // The main issue is that running sequencer service already passed
            // the moment of syncing up and in case if it fetching published non-finalized blocks,
            // then it is not actually representing for catching up, because blocks can be dropped
            // on a chain rearrangement.
            sync_status: FfiSequencerSyncStatus::Synced,
            chain_height: value.chain_height,
            failed_attempts: value.failed_attempts,
            blocked_attempts_count: value.blocked_attempts_count,
            blocked_attempts_behind: value.blocked_attempts_behind.into(),
            stall_reason,
        })
    }
}

impl TryFrom<FfiSequencerStatus> for GetStatusReply {
    type Error = OperationStatus;

    fn try_from(value: FfiSequencerStatus) -> Result<Self, Self::Error> {
        if value.stall_reason.is_null() {
            return Err(OperationStatus::CastError);
        }

        let c_string = unsafe { CString::from_raw(value.stall_reason) };

        let json = c_string.to_str().map_err(|e| {
            log::error!("Stall reason is not valid UTF-8: {e}");
            OperationStatus::CastError
        })?;

        let stall_reason = serde_json::from_str(json).map_err(|e| {
            log::error!("Failed to deserialize stall reason: {e}");
            OperationStatus::CastError
        })?;

        let blocked_attempts_behind: Option<[u8; 32]> = value.blocked_attempts_behind.into();

        Ok(Self {
            chain_height: value.chain_height,
            failed_attempts: value.failed_attempts,
            blocked_attempts_count: value.blocked_attempts_count,
            blocked_attempts_behind,
            stall_reason,
        })
    }
}

/// 32-byte array type for `AccountId`, keys, hashes, etc.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct FfiBytes32 {
    pub data: [u8; 32],
}

/// 8-byte array type for event selectors.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct FfiBytes8 {
    pub data: [u8; 8],
}

/// 64-byte array type for signatures, etc.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FfiBytes64 {
    pub data: [u8; 64],
}

/// Program ID - 8 u32 values (32 bytes total).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiProgramId {
    pub data: [u32; 8],
}

impl From<ProgramId> for FfiProgramId {
    fn from(value: ProgramId) -> Self {
        Self { data: value }
    }
}

/// U128 - 16 bytes little endian.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiU128 {
    pub data: [u8; 16],
}

impl FfiBytes32 {
    /// Create from a 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { data: bytes }
    }

    /// Create from an `AccountId`.
    #[must_use]
    pub const fn from_account_id(id: &lee::AccountId) -> Self {
        Self { data: *id.value() }
    }
}

impl From<u128> for FfiU128 {
    fn from(value: u128) -> Self {
        Self {
            data: value.to_le_bytes(),
        }
    }
}

impl From<FfiU128> for u128 {
    fn from(value: FfiU128) -> Self {
        Self::from_le_bytes(value.data)
    }
}

impl From<Nonce> for FfiU128 {
    fn from(value: Nonce) -> Self {
        value.0.into()
    }
}

impl From<FfiU128> for Nonce {
    fn from(value: FfiU128) -> Self {
        Self(value.into())
    }
}

pub type FfiHashType = FfiBytes32;
pub type FfiBlockId = u64;
pub type FfiTimestamp = u64;
pub type FfiSignature = FfiBytes64;
pub type FfiAccountId = FfiBytes32;
pub type FfiNonce = FfiU128;
pub type FfiPublicKey = FfiBytes32;
pub type FfiSelector = FfiBytes8;

impl From<Selector> for FfiSelector {
    fn from(value: Selector) -> Self {
        Self { data: value.0 }
    }
}

impl From<FfiSelector> for Selector {
    fn from(value: FfiSelector) -> Self {
        Self(value.data)
    }
}

impl From<AccountId> for FfiBytes32 {
    fn from(value: AccountId) -> Self {
        Self {
            data: value.to_bytes(),
        }
    }
}

impl From<HashType> for FfiHashType {
    fn from(value: HashType) -> Self {
        Self { data: value.0 }
    }
}

impl From<FfiBytes32> for HashType {
    fn from(value: FfiBytes32) -> Self {
        Self(value.data)
    }
}

impl From<FfiBytes32> for AccountId {
    fn from(value: FfiBytes32) -> Self {
        Self::new(value.data)
    }
}

impl From<Signature> for FfiSignature {
    fn from(value: Signature) -> Self {
        Self { data: value.value }
    }
}

impl From<PublicKey> for FfiPublicKey {
    fn from(value: PublicKey) -> Self {
        Self {
            data: *value.value(),
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct FfiVec<T> {
    pub entries: *mut T,
    pub len: usize,
    pub capacity: usize,
}

impl<T> From<Vec<T>> for FfiVec<T> {
    fn from(value: Vec<T>) -> Self {
        let (entries, len, capacity) = value.into_raw_parts();
        Self {
            entries,
            len,
            capacity,
        }
    }
}

impl<T> From<FfiVec<T>> for Vec<T> {
    fn from(value: FfiVec<T>) -> Self {
        unsafe { Self::from_raw_parts(value.entries, value.len, value.capacity) }
    }
}

impl<T> FfiVec<T> {
    /// # Safety
    ///
    /// `index` must be lesser than `self.len`.
    #[must_use]
    pub unsafe fn get(&self, index: usize) -> &T {
        let ptr = unsafe { self.entries.add(index) };
        unsafe { &*ptr }
    }
}

#[repr(C)]
pub struct FfiOption<T> {
    pub value: *mut T,
    pub is_some: bool,
}

impl<T> FfiOption<T> {
    pub fn from_value(val: T) -> Self {
        Self {
            value: Box::into_raw(Box::new(val)),
            is_some: true,
        }
    }

    #[must_use]
    pub const fn from_none() -> Self {
        Self {
            value: std::ptr::null_mut(),
            is_some: false,
        }
    }
}

impl<T> From<Option<T>> for FfiOption<T> {
    fn from(value: Option<T>) -> Self {
        value.map_or_else(Self::from_none, |val| Self::from_value(val))
    }
}

impl<T> From<FfiOption<T>> for Option<T> {
    fn from(value: FfiOption<T>) -> Self {
        value.is_some.then(|| unsafe { value.value.read() })
    }
}

/// Frees the resources associated with the given sequencer status object.
///
/// Takes ownership of the whole allocation produced by `sequencer_ffi_query_status`: the outer
/// `Box<FfiSequencerStatus>` (the `PointerResult.value` pointer), and inner object.
///
/// # Arguments
///
/// - `val`: The `*mut FfiSequencerStatus` returned in `PointerResult.value`.
///
/// # Returns
///
/// void.
///
/// # Safety
///
/// The caller must ensure that:
/// - `val` is a pointer to an `FfiSequencerStatus` produced by this library and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_ffi_sequencer_status(val: *mut FfiSequencerStatus) {
    if val.is_null() {
        log::error!("Trying to free a null pointer. Exiting");
        return;
    }

    let ffi_status = unsafe { Box::from_raw(val) };
    let status: Result<GetStatusReply, OperationStatus> = (*ffi_status)
        .try_into()
        .inspect_err(|err| log::error!("Failed to drop FfiSequencerStatus: {err:?}"));

    drop(status);
}
