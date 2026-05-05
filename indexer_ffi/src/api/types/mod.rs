use indexer_service_protocol::{AccountId, HashType, MantleMsgId, ProgramId, PublicKey, Signature};

pub mod account;
pub mod block;
pub mod transaction;
pub mod vectors;

/// 32-byte array type for `AccountId`, keys, hashes, etc.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FfiBytes32 {
    pub data: [u8; 32],
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
        Self { data: value.0 }
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
    pub const fn from_account_id(id: &nssa::AccountId) -> Self {
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
