use indexer_service_protocol::{AccountId, HashType, MantleMsgId, PublicKey, Signature};

use crate::api::types::account::{FfiBytes32, FfiBytes64, FfiU128};

pub mod account;
pub mod block;
pub mod transaction;
pub mod vectors;

pub type FfiHashType = FfiBytes32;
pub type FfiMsgId = FfiBytes32;
pub type FfiBlockId = u64;
pub type FfiTimestamp = u64;
pub type FfiSignature = FfiBytes64;
pub type FfiAccountId = FfiBytes32;
pub type FfiNonce = FfiU128;
pub type FfiPublicKey = FfiBytes32;

impl From<HashType> for FfiHashType {
    fn from(value: HashType) -> Self {
        Self { data: value.0 }
    }
}

impl From<MantleMsgId> for FfiMsgId {
    fn from(value: MantleMsgId) -> Self {
        Self { data: value.0 }
    }
}

impl From<Signature> for FfiSignature {
    fn from(value: Signature) -> Self {
        Self { data: value.0 }
    }
}

impl From<AccountId> for FfiAccountId {
    fn from(value: AccountId) -> Self {
        Self { data: value.value }
    }
}

impl From<PublicKey> for FfiPublicKey {
    fn from(value: PublicKey) -> Self {
        Self { data: value.0 }
    }
}

#[repr(C)]
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
