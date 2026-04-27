use crate::api::types::account::{FfiBytes32, FfiBytes64, FfiU128};

pub mod account;
pub mod block;
pub mod transaction;

pub type FfiHashType = FfiBytes32;
pub type FfiMsgId = FfiBytes32;
pub type FfiBlockId = u64;
pub type FfiTimestamp = u64;
pub type FfiSignature = FfiBytes64;
pub type FfiAccountId = FfiBytes32;
pub type FfiNonce = FfiU128;
pub type FfiPublicKey = FfiBytes32;

#[repr(C)]
pub struct FfiVec<T> {
    pub entries: *const T,
    pub len: usize,
}

impl<T> Default for FfiVec<T> {
    fn default() -> Self {
        Self {
            entries: std::ptr::null(),
            len: 0,
        }
    }
}
