pub use ffi_types::{
    FfiAccountId, FfiBytes32, FfiBytes64, FfiNonce, FfiPublicKey, FfiSignature, FfiU128, FfiVec,
};
use indexer_service_protocol::Selector;

pub mod account;
pub mod block;
pub mod event;
pub mod transaction;
pub mod vectors;

/// 8-byte array type for event selectors.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiBytes8 {
    pub data: [u8; 8],
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
