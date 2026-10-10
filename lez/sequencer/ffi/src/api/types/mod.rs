pub use ffi_types::{
    FfiAccountId, FfiBytes32, FfiBytes64, FfiNonce, FfiPublicKey, FfiSignature, FfiU128, FfiVec,
};
use lee::ProgramId;
use sequencer_storage_actor::actor::event_filter::Selector;

pub mod account;
pub mod block;
pub mod event;
pub mod transaction;
pub mod vectors;

/// 8-byte array type for event selectors.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct FfiBytes8 {
    pub data: [u8; 8],
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

pub type FfiHashType = FfiBytes32;
pub type FfiBlockId = u64;
pub type FfiTimestamp = u64;
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
